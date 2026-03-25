package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	appsdomain "github.com/miloyuans/openauthing/internal/apps/domain"
	"github.com/miloyuans/openauthing/internal/config"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/validate"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type ApplicationRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (appsdomain.Application, error)
}

type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error)
	ListGroupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
}

type ServiceProviderRepository interface {
	GetByAppID(ctx context.Context, appID uuid.UUID) (samldomain.ServiceProvider, error)
	GetByEntityID(ctx context.Context, entityID string) (samldomain.ServiceProvider, error)
	Upsert(ctx context.Context, sp samldomain.ServiceProvider) (samldomain.ServiceProvider, error)
}

type CertificateManager interface {
	MetadataCertificate() string
	Certificate() *x509.Certificate
	PrivateKey() *rsa.PrivateKey
}

type Service struct {
	cfg           config.SAMLConfig
	issuer        string
	apps          ApplicationRepository
	users         UserRepository
	repo          ServiceProviderRepository
	certs         CertificateManager
	sessionSecret string
	logger        *slog.Logger
	now           func() time.Time
}

func NewService(
	cfg config.SAMLConfig,
	issuer string,
	apps ApplicationRepository,
	users UserRepository,
	repo ServiceProviderRepository,
	certs CertificateManager,
	sessionSecret string,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}

	return &Service{
		cfg:           cfg,
		issuer:        strings.TrimRight(strings.TrimSpace(issuer), "/"),
		apps:          apps,
		users:         users,
		repo:          repo,
		certs:         certs,
		sessionSecret: strings.TrimSpace(sessionSecret),
		logger:        logger,
		now:           time.Now,
	}
}

func (s *Service) GetByAppID(ctx context.Context, rawAppID string) (samldomain.ServiceProvider, error) {
	app, err := s.loadSAMLApplication(ctx, rawAppID)
	if err != nil {
		return samldomain.ServiceProvider{}, err
	}

	sp, err := s.repo.GetByAppID(ctx, app.ID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return samldomain.ServiceProvider{}, apierror.NotFound("saml service provider configuration not found")
		default:
			return samldomain.ServiceProvider{}, err
		}
	}

	return normalizeServiceProvider(sp), nil
}

func (s *Service) Upsert(ctx context.Context, rawAppID string, input samldomain.UpsertServiceProviderInput) (samldomain.ServiceProvider, error) {
	app, err := s.loadSAMLApplication(ctx, rawAppID)
	if err != nil {
		return samldomain.ServiceProvider{}, err
	}

	sp := samldomain.ServiceProvider{
		AppID:                app.ID,
		EntityID:             strings.TrimSpace(input.EntityID),
		ACSURL:               strings.TrimSpace(input.ACSURL),
		SLOURL:               strings.TrimSpace(input.SLOURL),
		NameIDFormat:         normalizedNameIDFormat(input.NameIDFormat),
		WantAssertionsSigned: input.WantAssertionsSigned,
		WantResponseSigned:   input.WantResponseSigned,
		SignAuthnRequest:     input.SignAuthnRequest,
		EncryptAssertion:     input.EncryptAssertion,
		SPMetadataXML:        strings.TrimSpace(input.SPMetadataXML),
		SPX509Cert:           compactCertificate(input.SPX509Cert),
		AttributeMapping:     cloneMapping(input.AttributeMapping),
	}

	if sp.NameIDFormat == "" {
		sp.NameIDFormat = samldomain.DefaultNameIDFormat
	}

	fieldErrors := map[string]string{}
	validate.Required("entity_id", sp.EntityID, fieldErrors)
	validate.URL("acs_url", sp.ACSURL, fieldErrors)
	validate.URL("slo_url", sp.SLOURL, fieldErrors)

	if sp.ACSURL == "" {
		fieldErrors["acs_url"] = "is required"
	}

	if len(fieldErrors) > 0 {
		return samldomain.ServiceProvider{}, apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	created, err := s.repo.Upsert(ctx, sp)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return samldomain.ServiceProvider{}, apierror.Conflict("saml service provider already exists", nil)
		default:
			return samldomain.ServiceProvider{}, err
		}
	}

	return normalizeServiceProvider(created), nil
}

func (s *Service) ImportMetadata(ctx context.Context, rawAppID, metadataXML string) (samldomain.ServiceProvider, error) {
	app, err := s.loadSAMLApplication(ctx, rawAppID)
	if err != nil {
		return samldomain.ServiceProvider{}, err
	}

	imported, err := parseServiceProviderMetadata(metadataXML)
	if err != nil {
		return samldomain.ServiceProvider{}, apierror.Validation(map[string]any{
			"fields": map[string]string{"metadata_xml": err.Error()},
		})
	}

	base := defaultServiceProvider(app.ID)
	existing, err := s.repo.GetByAppID(ctx, app.ID)
	switch {
	case err == nil:
		base = normalizeServiceProvider(existing)
	case errors.Is(err, store.ErrNotFound):
	default:
		return samldomain.ServiceProvider{}, err
	}

	base.EntityID = imported.EntityID
	base.ACSURL = imported.ACSURL
	base.SLOURL = imported.SLOURL
	base.NameIDFormat = imported.NameIDFormat
	base.WantAssertionsSigned = imported.WantAssertionsSigned
	base.SignAuthnRequest = imported.SignAuthnRequest
	base.EncryptAssertion = imported.EncryptAssertion
	base.SPMetadataXML = strings.TrimSpace(metadataXML)
	base.SPX509Cert = compactCertificate(imported.SPX509Cert)

	created, err := s.repo.Upsert(ctx, normalizeServiceProvider(base))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return samldomain.ServiceProvider{}, apierror.Conflict("saml service provider already exists", nil)
		default:
			return samldomain.ServiceProvider{}, err
		}
	}

	return normalizeServiceProvider(created), nil
}

func (s *Service) IDPMetadata() ([]byte, error) {
	if s.certs == nil {
		return nil, fmt.Errorf("saml certificate manager is not configured")
	}

	document := entityDescriptor{
		XMLNS:   "urn:oasis:names:tc:SAML:2.0:metadata",
		XMLNSDS: "http://www.w3.org/2000/09/xmldsig#",
		EntityID: s.idpEntityID(),
		IDPSSODescriptor: idpSSODescriptor{
			ProtocolSupportEnumeration: samldomain.ProtocolNamespaceSAML20,
			KeyDescriptor: keyDescriptor{
				Use: "signing",
				KeyInfo: dsKeyInfo{
					X509Data: dsX509Data{
						X509Certificate: s.certs.MetadataCertificate(),
					},
				},
			},
			NameIDFormat: samldomain.DefaultNameIDFormat,
			SingleSignOnService: endpoint{
				Binding:  samldomain.BindingHTTPRedirect,
				Location: s.endpoint("/saml/idp/sso"),
			},
			SingleLogoutService: endpoint{
				Binding:  samldomain.BindingHTTPRedirect,
				Location: s.endpoint("/saml/idp/slo"),
			},
		},
	}

	body, err := xml.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal saml idp metadata: %w", err)
	}

	return append([]byte(xml.Header), body...), nil
}

func (s *Service) loadSAMLApplication(ctx context.Context, rawAppID string) (appsdomain.Application, error) {
	appID, err := uuid.Parse(strings.TrimSpace(rawAppID))
	if err != nil {
		return appsdomain.Application{}, apierror.Validation(map[string]any{
			"fields": map[string]string{"app_id": "must be a valid UUID"},
		})
	}

	app, err := s.apps.GetByID(ctx, appID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return appsdomain.Application{}, apierror.NotFound("application not found")
		default:
			return appsdomain.Application{}, err
		}
	}

	if app.Type != appsdomain.TypeSAMLSP {
		return appsdomain.Application{}, apierror.Validation(map[string]any{
			"fields": map[string]string{"app_id": "application must be type saml-sp"},
		})
	}

	return app, nil
}

func (s *Service) idpEntityID() string {
	if value := strings.TrimSpace(s.cfg.IDPEntityID); value != "" {
		return value
	}

	return s.endpoint("/saml/idp/metadata")
}

func (s *Service) endpoint(path string) string {
	return s.issuer + path
}

func defaultServiceProvider(appID uuid.UUID) samldomain.ServiceProvider {
	return samldomain.ServiceProvider{
		AppID:            appID,
		NameIDFormat:     samldomain.DefaultNameIDFormat,
		AttributeMapping: map[string]string{},
	}
}

func normalizeServiceProvider(sp samldomain.ServiceProvider) samldomain.ServiceProvider {
	if sp.NameIDFormat == "" {
		sp.NameIDFormat = samldomain.DefaultNameIDFormat
	}
	sp.NameIDFormat = normalizedNameIDFormat(sp.NameIDFormat)
	sp.SPX509Cert = compactCertificate(sp.SPX509Cert)
	sp.AttributeMapping = cloneMapping(sp.AttributeMapping)
	return sp
}

func cloneMapping(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}

	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	return cloned
}

func compactCertificate(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}

	return strings.Join(strings.Fields(raw), "")
}

type entityDescriptor struct {
	XMLName          xml.Name         `xml:"EntityDescriptor"`
	XMLNS            string           `xml:"xmlns,attr"`
	XMLNSDS          string           `xml:"xmlns:ds,attr"`
	EntityID         string           `xml:"entityID,attr"`
	IDPSSODescriptor idpSSODescriptor `xml:"IDPSSODescriptor"`
}

type idpSSODescriptor struct {
	ProtocolSupportEnumeration string       `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              keyDescriptor `xml:"KeyDescriptor"`
	NameIDFormat               string       `xml:"NameIDFormat"`
	SingleSignOnService        endpoint     `xml:"SingleSignOnService"`
	SingleLogoutService        endpoint     `xml:"SingleLogoutService"`
}

type keyDescriptor struct {
	Use     string    `xml:"use,attr,omitempty"`
	KeyInfo dsKeyInfo `xml:"ds:KeyInfo"`
}

type dsKeyInfo struct {
	X509Data dsX509Data `xml:"ds:X509Data"`
}

type dsX509Data struct {
	X509Certificate string `xml:"ds:X509Certificate"`
}

type endpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type importedMetadata struct {
	EntityID             string
	ACSURL               string
	SLOURL               string
	NameIDFormat         string
	WantAssertionsSigned bool
	SignAuthnRequest     bool
	EncryptAssertion     bool
	SPX509Cert           string
}

type importedEntityDescriptor struct {
	XMLName         xml.Name               `xml:"EntityDescriptor"`
	EntityID        string                 `xml:"entityID,attr"`
	SPSSODescriptor importedSPSSODescriptor `xml:"SPSSODescriptor"`
}

type importedEntitiesDescriptor struct {
	XMLName           xml.Name                   `xml:"EntitiesDescriptor"`
	EntityDescriptors []importedEntityDescriptor `xml:"EntityDescriptor"`
}

type importedSPSSODescriptor struct {
	WantAssertionsSigned   bool                      `xml:"WantAssertionsSigned,attr"`
	AuthnRequestsSigned    bool                      `xml:"AuthnRequestsSigned,attr"`
	NameIDFormats          []string                  `xml:"NameIDFormat"`
	AssertionConsumerItems []importedEndpoint       `xml:"AssertionConsumerService"`
	SingleLogoutItems      []importedEndpoint       `xml:"SingleLogoutService"`
	KeyDescriptors         []importedKeyDescriptor  `xml:"KeyDescriptor"`
}

type importedEndpoint struct {
	Location string `xml:"Location,attr"`
}

type importedKeyDescriptor struct {
	Use     string             `xml:"use,attr"`
	KeyInfo importedKeyInfo    `xml:"KeyInfo"`
}

type importedKeyInfo struct {
	X509Data importedX509Data `xml:"X509Data"`
}

type importedX509Data struct {
	X509Certificates []string `xml:"X509Certificate"`
}

func parseServiceProviderMetadata(raw string) (importedMetadata, error) {
	metadataXML := strings.TrimSpace(raw)
	if metadataXML == "" {
		return importedMetadata{}, fmt.Errorf("must not be empty")
	}

	entity, err := parseEntityDescriptor(metadataXML)
	if err != nil {
		return importedMetadata{}, err
	}

	if strings.TrimSpace(entity.EntityID) == "" {
		return importedMetadata{}, fmt.Errorf("entityID is required")
	}

	if len(entity.SPSSODescriptor.AssertionConsumerItems) == 0 || strings.TrimSpace(entity.SPSSODescriptor.AssertionConsumerItems[0].Location) == "" {
		return importedMetadata{}, fmt.Errorf("AssertionConsumerService is required")
	}

	nameIDFormat := samldomain.DefaultNameIDFormat
	if len(entity.SPSSODescriptor.NameIDFormats) > 0 && strings.TrimSpace(entity.SPSSODescriptor.NameIDFormats[0]) != "" {
		nameIDFormat = strings.TrimSpace(entity.SPSSODescriptor.NameIDFormats[0])
	}

	sloURL := ""
	if len(entity.SPSSODescriptor.SingleLogoutItems) > 0 {
		sloURL = strings.TrimSpace(entity.SPSSODescriptor.SingleLogoutItems[0].Location)
	}

	certificate := ""
	encryptAssertion := false
	for _, item := range entity.SPSSODescriptor.KeyDescriptors {
		for _, value := range item.KeyInfo.X509Data.X509Certificates {
			if compacted := compactCertificate(value); certificate == "" && compacted != "" {
				certificate = compacted
				break
			}
		}

		if strings.EqualFold(strings.TrimSpace(item.Use), "encryption") {
			encryptAssertion = true
		}
	}

	return importedMetadata{
		EntityID:             strings.TrimSpace(entity.EntityID),
		ACSURL:               strings.TrimSpace(entity.SPSSODescriptor.AssertionConsumerItems[0].Location),
		SLOURL:               sloURL,
		NameIDFormat:         nameIDFormat,
		WantAssertionsSigned: entity.SPSSODescriptor.WantAssertionsSigned,
		SignAuthnRequest:     entity.SPSSODescriptor.AuthnRequestsSigned,
		EncryptAssertion:     encryptAssertion,
		SPX509Cert:           certificate,
	}, nil
}

func parseEntityDescriptor(raw string) (importedEntityDescriptor, error) {
	var entity importedEntityDescriptor
	if err := xml.Unmarshal([]byte(raw), &entity); err == nil && (entity.EntityID != "" || len(entity.SPSSODescriptor.AssertionConsumerItems) > 0 || entity.XMLName.Local == "EntityDescriptor") {
		return entity, nil
	}

	var entities importedEntitiesDescriptor
	if err := xml.Unmarshal([]byte(raw), &entities); err != nil {
		return importedEntityDescriptor{}, fmt.Errorf("must be valid SAML metadata XML")
	}

	if len(entities.EntityDescriptors) == 0 {
		return importedEntityDescriptor{}, fmt.Errorf("EntityDescriptor not found")
	}

	return entities.EntityDescriptors[0], nil
}
