package service

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	casdomain "github.com/miloyuans/openauthing/internal/cas/domain"
	casrepo "github.com/miloyuans/openauthing/internal/cas/repo"
	"github.com/miloyuans/openauthing/internal/cas/ticketvalue"
	"github.com/miloyuans/openauthing/internal/config"
	"github.com/miloyuans/openauthing/internal/shared/requestid"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

const (
	defaultServiceTicketTTL = time.Minute
	casNamespace            = "http://www.yale.edu/tp/cas"
)

type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error)
	ListGroupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
}

type TxManager interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type TicketValueManager interface {
	Generate(prefix string) (string, error)
	Hash(secret, rawValue string) (string, error)
}

type Service struct {
	cfg          config.CASConfig
	users        UserRepository
	tickets      casrepo.TicketRepository
	txManager     TxManager
	ticketValues TicketValueManager
	ticketSecret string
	logger       *slog.Logger
	now          func() time.Time
}

type defaultTicketValueManager struct{}

func (defaultTicketValueManager) Generate(prefix string) (string, error) {
	return ticketvalue.Generate(prefix)
}

func (defaultTicketValueManager) Hash(secret, rawValue string) (string, error) {
	return ticketvalue.Hash(secret, rawValue)
}

func NewService(
	cfg config.CASConfig,
	users UserRepository,
	tickets casrepo.TicketRepository,
	txManager TxManager,
	ticketSecret string,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.ServiceTicketTTLSeconds <= 0 {
		cfg.ServiceTicketTTLSeconds = int(defaultServiceTicketTTL / time.Second)
	}

	return &Service{
		cfg:          cfg,
		users:        users,
		tickets:      tickets,
		txManager:     txManager,
		ticketValues: defaultTicketValueManager{},
		ticketSecret: strings.TrimSpace(ticketSecret),
		logger:       logger,
		now:          time.Now,
	}
}

func (s *Service) NormalizeService(rawService string) (string, error) {
	service := strings.TrimSpace(rawService)
	if service == "" {
		return "", casdomain.ProtocolError{
			Status:  httpStatusBadRequest,
			Code:    casdomain.FailureCodeInvalidRequest,
			Message: "service is required",
		}
	}

	parsed, err := neturl.Parse(service)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || strings.TrimSpace(parsed.Host) == "" {
		return "", casdomain.ProtocolError{
			Status:  httpStatusBadRequest,
			Code:    casdomain.FailureCodeInvalidService,
			Message: "service must be a valid absolute URL",
		}
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if len(s.cfg.AllowedServiceHosts) > 0 {
		allowed := false
		for _, value := range s.cfg.AllowedServiceHosts {
			if strings.EqualFold(strings.TrimSpace(value), host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", casdomain.ProtocolError{
				Status:  httpStatusBadRequest,
				Code:    casdomain.FailureCodeInvalidService,
				Message: "service host is not allowed",
			}
		}
	}

	parsed.Fragment = ""
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), nil
}

func (s *Service) Login(ctx context.Context, session authdomain.Session, rawService string) (string, error) {
	service, err := s.NormalizeService(rawService)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(s.ticketSecret) == "" {
		return "", casdomain.ProtocolError{
			Status:  httpStatusInternalServerError,
			Code:    casdomain.FailureCodeInternalError,
			Message: "session secret is required for cas ticket issuance",
		}
	}

	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", casdomain.ProtocolError{
				Status:  httpStatusBadRequest,
				Code:    casdomain.FailureCodeInvalidRequest,
				Message: "current user does not exist",
			}
		}
		return "", err
	}
	if user.Status != "active" {
		return "", casdomain.ProtocolError{
			Status:  httpStatusBadRequest,
			Code:    casdomain.FailureCodeInvalidRequest,
			Message: "current user is not active",
		}
	}

	var rawServiceTicket string
	err = s.withinTx(ctx, func(txCtx context.Context) error {
		now := s.now().UTC()
		tgt, lookupErr := s.tickets.GetActiveTGTBySessionID(txCtx, session.ID, now)
		switch {
		case lookupErr == nil:
		case errors.Is(lookupErr, store.ErrNotFound):
			createdTGT, _, createErr := s.createTicket(txCtx, casdomain.TicketTypeTGT, "", session.UserID, session.ID, nil, session.ExpiresAt.UTC())
			if createErr != nil {
				return createErr
			}
			tgt = createdTGT
		default:
			return lookupErr
		}

		rawServiceTicket, err = s.createServiceTicket(txCtx, service, session.UserID, session.ID, tgt.ID)
		return err
	})
	if err != nil {
		return "", err
	}

	s.logger.Info("cas service ticket issued",
		"request_id", requestid.FromContext(ctx),
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
		"service", service,
	)

	return rawServiceTicket, nil
}

func (s *Service) ValidateServiceTicket(ctx context.Context, rawService, rawTicket string, withAttributes bool) (casdomain.ValidationResult, error) {
	service, err := s.NormalizeService(rawService)
	if err != nil {
		return casdomain.ValidationResult{}, err
	}

	trimmedTicket := strings.TrimSpace(rawTicket)
	if trimmedTicket == "" {
		return casdomain.ValidationResult{}, casdomain.ProtocolError{
			Status:  httpStatusBadRequest,
			Code:    casdomain.FailureCodeInvalidRequest,
			Message: "ticket is required",
		}
	}

	if strings.TrimSpace(s.ticketSecret) == "" {
		return casdomain.ValidationResult{}, casdomain.ProtocolError{
			Status:  httpStatusInternalServerError,
			Code:    casdomain.FailureCodeInternalError,
			Message: "session secret is required for cas ticket validation",
		}
	}

	hashedTicket, err := s.ticketValues.Hash(s.ticketSecret, trimmedTicket)
	if err != nil {
		return casdomain.ValidationResult{}, casdomain.ProtocolError{
			Status:  httpStatusInternalServerError,
			Code:    casdomain.FailureCodeInternalError,
			Message: "failed to hash cas ticket",
		}
	}

	now := s.now().UTC()
	var result casdomain.ValidationResult
	err = s.withinTx(ctx, func(txCtx context.Context) error {
		ticket, lookupErr := s.tickets.GetByTicketForUpdate(txCtx, hashedTicket)
		if lookupErr != nil {
			if errors.Is(lookupErr, store.ErrNotFound) {
				return casdomain.ProtocolError{
					Status:  httpStatusOK,
					Code:    casdomain.FailureCodeInvalidTicket,
					Message: "ticket not recognized",
				}
			}
			return lookupErr
		}

		if ticket.Type != casdomain.TicketTypeST {
			return casdomain.ProtocolError{
				Status:  httpStatusOK,
				Code:    casdomain.FailureCodeInvalidTicket,
				Message: "ticket is not a service ticket",
			}
		}
		if ticket.ConsumedAt != nil {
			return casdomain.ProtocolError{
				Status:  httpStatusOK,
				Code:    casdomain.FailureCodeInvalidTicket,
				Message: "ticket has already been consumed",
			}
		}
		if !now.Before(ticket.ExpiresAt) {
			return casdomain.ProtocolError{
				Status:  httpStatusOK,
				Code:    casdomain.FailureCodeInvalidTicket,
				Message: "ticket has expired",
			}
		}
		if ticket.Service != service {
			if consumeErr := s.tickets.Consume(txCtx, ticket.ID, now); consumeErr != nil && !errors.Is(consumeErr, store.ErrNotFound) {
				return consumeErr
			}
			return casdomain.ProtocolError{
				Status:  httpStatusOK,
				Code:    casdomain.FailureCodeInvalidService,
				Message: "ticket does not match the supplied service",
			}
		}

		user, userErr := s.users.GetByID(txCtx, ticket.UserID)
		if userErr != nil {
			if errors.Is(userErr, store.ErrNotFound) {
				return casdomain.ProtocolError{
					Status:  httpStatusOK,
					Code:    casdomain.FailureCodeInvalidTicket,
					Message: "ticket subject no longer exists",
				}
			}
			return userErr
		}
		if user.Status != "active" {
			return casdomain.ProtocolError{
				Status:  httpStatusOK,
				Code:    casdomain.FailureCodeInvalidTicket,
				Message: "ticket subject is not active",
			}
		}

		if consumeErr := s.tickets.Consume(txCtx, ticket.ID, now); consumeErr != nil {
			if errors.Is(consumeErr, store.ErrNotFound) {
				return casdomain.ProtocolError{
					Status:  httpStatusOK,
					Code:    casdomain.FailureCodeInvalidTicket,
					Message: "ticket has already been consumed",
				}
			}
			return consumeErr
		}

		result.Username = user.Username
		if withAttributes {
			groups, groupErr := s.users.ListGroupCodes(txCtx, user.ID)
			if groupErr != nil {
				return groupErr
			}
			result.Attributes = casdomain.ValidationAttributes{
				Username:    user.Username,
				Email:       user.Email,
				DisplayName: user.DisplayName,
				Groups:      groups,
			}
		}
		return nil
	})
	if err != nil {
		return casdomain.ValidationResult{}, err
	}

	s.logger.Info("cas service ticket validated",
		"request_id", requestid.FromContext(ctx),
		"username", result.Username,
		"service", service,
	)

	return result, nil
}

func (s *Service) ServiceResponseXML(result casdomain.ValidationResult, withAttributes bool) ([]byte, error) {
	response := serviceResponse{
		XMLNSCAS: casNamespace,
		Success: &authenticationSuccess{
			User: result.Username,
		},
	}

	if withAttributes {
		username := result.Attributes.Username
		if username == "" {
			username = result.Username
		}
		response.Success.Attributes = &casAttributes{
			Username:    username,
			Email:       result.Attributes.Email,
			DisplayName: result.Attributes.DisplayName,
			Groups:      sliceOrEmpty(result.Attributes.Groups),
		}
	}

	body, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal cas service response: %w", err)
	}

	return append([]byte(xml.Header), body...), nil
}

func (s *Service) FailureResponseXML(code, message string) ([]byte, error) {
	response := serviceResponse{
		XMLNSCAS: casNamespace,
		Failure: &authenticationFailure{
			Code:    code,
			Message: message,
		},
	}

	body, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal cas failure response: %w", err)
	}

	return append([]byte(xml.Header), body...), nil
}

func (s *Service) createServiceTicket(ctx context.Context, service string, userID, sessionID uuid.UUID, parentTicketID uuid.UUID) (string, error) {
	_, rawTicket, err := s.createTicket(ctx, casdomain.TicketTypeST, service, userID, sessionID, &parentTicketID, s.now().UTC().Add(time.Duration(s.cfg.ServiceTicketTTLSeconds)*time.Second))
	if err != nil {
		return "", err
	}

	return rawTicket, nil
}

func (s *Service) createTicket(
	ctx context.Context,
	ticketType string,
	service string,
	userID uuid.UUID,
	sessionID uuid.UUID,
	parentTicketID *uuid.UUID,
	expiresAt time.Time,
) (casdomain.Ticket, string, error) {
	rawTicket, err := s.ticketValues.Generate(ticketType)
	if err != nil {
		return casdomain.Ticket{}, "", fmt.Errorf("generate cas ticket: %w", err)
	}

	hashedTicket, err := s.ticketValues.Hash(s.ticketSecret, rawTicket)
	if err != nil {
		return casdomain.Ticket{}, "", fmt.Errorf("hash cas ticket: %w", err)
	}

	created, err := s.tickets.Create(ctx, casdomain.Ticket{
		Ticket:         hashedTicket,
		Type:           ticketType,
		Service:        service,
		UserID:         userID,
		SessionID:      sessionID,
		ParentTicketID: parentTicketID,
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		return casdomain.Ticket{}, "", err
	}

	return created, rawTicket, nil
}

func (s *Service) withinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.txManager == nil {
		return fn(ctx)
	}

	return s.txManager.WithinTx(ctx, fn)
}

func sliceOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}

const (
	httpStatusOK                  = 200
	httpStatusBadRequest          = 400
	httpStatusInternalServerError = 500
)

type serviceResponse struct {
	XMLName  xml.Name               `xml:"cas:serviceResponse"`
	XMLNSCAS string                 `xml:"xmlns:cas,attr"`
	Success  *authenticationSuccess `xml:"cas:authenticationSuccess,omitempty"`
	Failure  *authenticationFailure `xml:"cas:authenticationFailure,omitempty"`
}

type authenticationSuccess struct {
	User       string         `xml:"cas:user"`
	Attributes *casAttributes `xml:"cas:attributes,omitempty"`
}

type casAttributes struct {
	Username    string   `xml:"cas:username,omitempty"`
	Email       string   `xml:"cas:email,omitempty"`
	DisplayName string   `xml:"cas:display_name,omitempty"`
	Groups      []string `xml:"cas:groups,omitempty"`
}

type authenticationFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}
