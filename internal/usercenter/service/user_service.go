package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	authpassword "github.com/miloyuans/openauthing/internal/auth/password"
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
	repo           repo.UserRepository
	passwordHasher PasswordHasher
}

type PasswordHasher interface {
	Hash(plain string) (string, error)
	Algorithm() string
}

func NewUserService(repo repo.UserRepository) *UserService {
	return NewUserServiceWithPasswordHasher(repo, authpassword.NewArgon2ID())
}

func NewUserServiceWithPasswordHasher(repo repo.UserRepository, passwordHasher PasswordHasher) *UserService {
	if passwordHasher == nil {
		passwordHasher = authpassword.NewArgon2ID()
	}

	return &UserService{
		repo:           repo,
		passwordHasher: passwordHasher,
	}
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
		PasswordHash: strings.TrimSpace(input.PasswordHash),
		PasswordAlgo: strings.TrimSpace(input.PasswordAlgo),
		Status:       strings.TrimSpace(input.Status),
		Source:       strings.TrimSpace(input.Source),
	}

	if err := applyCreatePassword(&model, input, s.passwordHasher); err != nil {
		return domain.User{}, err
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
	if err := applyUpdatePassword(&current, input, s.passwordHasher); err != nil {
		return domain.User{}, err
	}
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
		user.PasswordHash = strings.TrimSpace(*input.PasswordHash)
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

func applyCreatePassword(user *domain.User, input domain.CreateUserInput, hasher PasswordHasher) error {
	plainPassword := input.Password
	if strings.TrimSpace(plainPassword) == "" {
		return validatePasswordInputs(plainPassword, user.PasswordHash)
	}

	if err := validatePasswordInputs(plainPassword, user.PasswordHash); err != nil {
		return err
	}

	passwordHash, err := hasher.Hash(plainPassword)
	if err != nil {
		return apierror.Internal()
	}

	user.PasswordHash = passwordHash
	user.PasswordAlgo = hasher.Algorithm()
	return nil
}

func applyUpdatePassword(user *domain.User, input domain.UpdateUserInput, hasher PasswordHasher) error {
	if input.Password == nil {
		return validatePasswordInputs("", user.PasswordHash)
	}

	plainPassword := *input.Password
	if strings.TrimSpace(plainPassword) == "" {
		return apierror.Validation(map[string]any{
			"fields": map[string]string{"password": "is required"},
		})
	}
	if err := validatePasswordInputs(plainPassword, user.PasswordHash); err != nil {
		return err
	}

	passwordHash, err := hasher.Hash(plainPassword)
	if err != nil {
		return apierror.Internal()
	}

	user.PasswordHash = passwordHash
	user.PasswordAlgo = hasher.Algorithm()
	return nil
}

func validatePasswordInputs(password, passwordHash string) error {
	fieldErrors := map[string]string{}
	trimmedPassword := strings.TrimSpace(password)
	trimmedHash := strings.TrimSpace(passwordHash)

	if trimmedPassword != "" && trimmedHash != "" {
		fieldErrors["password"] = "password and password_hash cannot be used together"
		fieldErrors["password_hash"] = "password and password_hash cannot be used together"
	}
	if trimmedPassword != "" {
		validate.Password("password", password, fieldErrors)
	}
	if trimmedHash != "" {
		if err := authpassword.ValidateEncodedHash(trimmedHash); err != nil {
			fieldErrors["password_hash"] = "must be a valid argon2id encoded hash"
		}
	}

	if len(fieldErrors) > 0 {
		return apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	return nil
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
	validate.OneOf("password_algo", user.PasswordAlgo, []string{defaultPasswordAlgo}, fieldErrors)
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
