package service

import (
	"bytes"
	"context"
	"compress/flate"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/russellhaering/goxmldsig"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	appsdomain "github.com/miloyuans/openauthing/internal/apps/domain"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
	"github.com/miloyuans/openauthing/internal/shared/requestid"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

const (
	assertionLifetime        = 5 * time.Minute
	allowedClockSkew         = 2 * time.Minute
	assertionNS              = "urn:oasis:names:tc:SAML:2.0:assertion"
	authnContextPassword     = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	samlStatusSuccess        = "urn:oasis:names:tc:SAML:2.0:status:Success"
	subjectConfirmationBear  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

func (s *Service) CompleteSPInitiated(ctx context.Context, session authdomain.Session, input samldomain.SPInitiatedRequest) (samldomain.LoginResult, error) {
	request, err := parseSPInitiatedRequest(input)
	if err != nil {
		return samldomain.LoginResult{}, err
	}

	sp, err := s.repo.GetByEntityID(ctx, request.Issuer)
	if err != nil {
		if errorsIs(err, store.ErrNotFound) {
			return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "unknown service provider issuer"}
		}
		return samldomain.LoginResult{}, err
	}

	if request.Destination != "" && request.Destination != s.endpoint("/saml/idp/sso") {
		return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "authn request destination does not match the IdP SSO endpoint"}
	}
	if request.ACSURL != "" && request.ACSURL != sp.ACSURL {
		return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "authn request ACS URL does not match the registered service provider ACS URL"}
	}

	app, err := s.apps.GetByID(ctx, sp.AppID)
	if err != nil {
		if errorsIs(err, store.ErrNotFound) {
			return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "service provider application not found"}
		}
		return samldomain.LoginResult{}, err
	}

	return s.issueLoginResult(ctx, session, app, normalizeServiceProvider(sp), request.ID, input.RelayState)
}

func (s *Service) CompleteIDPInitiated(ctx context.Context, session authdomain.Session, rawAppID, rawEntityID string) (samldomain.LoginResult, error) {
	rawAppID = strings.TrimSpace(rawAppID)
	rawEntityID = strings.TrimSpace(rawEntityID)
	if rawAppID == "" && rawEntityID == "" {
		return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "app_id or sp_entity_id is required"}
	}

	var (
		app appsdomain.Application
		sp  samldomain.ServiceProvider
		err error
	)

	switch {
	case rawAppID != "":
		app, err = s.loadSAMLApplication(ctx, rawAppID)
		if err != nil {
			return samldomain.LoginResult{}, protocolErrorFromAPIError(err)
		}
		sp, err = s.repo.GetByAppID(ctx, app.ID)
	case rawEntityID != "":
		sp, err = s.repo.GetByEntityID(ctx, rawEntityID)
		if err == nil {
			app, err = s.apps.GetByID(ctx, sp.AppID)
		}
	}
	if err != nil {
		if errorsIs(err, store.ErrNotFound) {
			return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusNotFound, Message: "service provider configuration not found"}
		}
		return samldomain.LoginResult{}, err
	}

	return s.issueLoginResult(ctx, session, app, normalizeServiceProvider(sp), "", "")
}

func (s *Service) issueLoginResult(
	ctx context.Context,
	session authdomain.Session,
	app appsdomain.Application,
	sp samldomain.ServiceProvider,
	inResponseTo string,
	relayState string,
) (samldomain.LoginResult, error) {
	if app.Type != appsdomain.TypeSAMLSP {
		return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "application must be type saml-sp"}
	}
	if app.Status == appsdomain.StatusDisabled {
		return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusForbidden, Message: "application is disabled"}
	}
	if session.TenantID != app.TenantID {
		return samldomain.LoginResult{}, samldomain.ProtocolError{Status: http.StatusForbidden, Message: "current session tenant does not match the service provider tenant"}
	}

	user, err := s.loadAssertionUser(ctx, session, app.TenantID)
	if err != nil {
		return samldomain.LoginResult{}, err
	}

	nameIDFormat := normalizedNameIDFormat(sp.NameIDFormat)
	nameIDValue, err := s.nameIDValue(user, sp.EntityID, nameIDFormat)
	if err != nil {
		return samldomain.LoginResult{}, err
	}

	responseXML, err := s.buildSignedResponse(ctx, session, user, sp, inResponseTo)
	if err != nil {
		return samldomain.LoginResult{}, err
	}

	if err := s.bindLoginSession(ctx, app.ID, user.ID, session.ID, nameIDValue, session.ID.String(), session.ExpiresAt.UTC()); err != nil {
		return samldomain.LoginResult{}, err
	}

	s.logger.Info("saml sso response issued",
		"request_id", requestid.FromContext(ctx),
		"user_id", user.ID.String(),
		"tenant_id", app.TenantID.String(),
		"app_id", app.ID.String(),
		"sp_entity_id", sp.EntityID,
		"session_id", session.ID.String(),
	)

	return samldomain.LoginResult{
		ACSURL:       sp.ACSURL,
		SAMLResponse: base64.StdEncoding.EncodeToString(responseXML),
		RelayState:   relayState,
		AppID:        app.ID.String(),
		EntityID:     sp.EntityID,
	}, nil
}

func (s *Service) bindLoginSession(ctx context.Context, appID, userID, sessionID uuid.UUID, nameID, sessionIndex string, expiresAt time.Time) error {
	if s.loginSessions == nil {
		return samldomain.ProtocolError{Status: http.StatusInternalServerError, Message: "saml login session repository is not configured"}
	}

	now := s.now().UTC()
	_, err := s.loginSessions.Upsert(ctx, samldomain.LoginSession{
		AppID:        appID,
		UserID:       userID,
		SessionID:    sessionID,
		NameID:       strings.TrimSpace(nameID),
		SessionIndex: strings.TrimSpace(sessionIndex),
		Status:       samldomain.LoginSessionStatusActive,
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
	})
	return err
}

func (s *Service) buildSignedResponse(
	ctx context.Context,
	session authdomain.Session,
	user userdomain.User,
	sp samldomain.ServiceProvider,
	inResponseTo string,
) ([]byte, error) {
	if s.certs == nil || s.certs.Certificate() == nil || s.certs.PrivateKey() == nil {
		return nil, samldomain.ProtocolError{Status: http.StatusInternalServerError, Message: "saml signing certificate is not configured"}
	}

	now := s.now().UTC()
	responseID := newSAMLID()
	assertionID := newSAMLID()

	response := etree.NewElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", samldomain.ProtocolNamespaceSAML20)
	response.CreateAttr("xmlns:saml", assertionNS)
	response.CreateAttr("xmlns:ds", goxmldsig.Namespace)
	response.CreateAttr("ID", responseID)
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", samlTime(now))
	response.CreateAttr("Destination", sp.ACSURL)
	if inResponseTo != "" {
		response.CreateAttr("InResponseTo", inResponseTo)
	}

	responseIssuer := response.CreateElement("saml:Issuer")
	responseIssuer.SetText(s.idpEntityID())

	status := response.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", samlStatusSuccess)

	assertion, err := s.buildAssertion(ctx, session, user, sp, assertionID, inResponseTo, now)
	if err != nil {
		return nil, err
	}

	if sp.WantAssertionsSigned {
		assertion, err = s.signElement(assertion)
		if err != nil {
			return nil, fmt.Errorf("sign saml assertion: %w", err)
		}
	}

	response.AddChild(assertion)

	if sp.WantResponseSigned {
		response, err = s.signElement(response)
		if err != nil {
			return nil, fmt.Errorf("sign saml response: %w", err)
		}
	}

	document := etree.NewDocument()
	document.WriteSettings = etree.WriteSettings{CanonicalText: true}
	document.SetRoot(response)
	raw, err := document.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize saml response: %w", err)
	}

	return raw, nil
}

func (s *Service) buildAssertion(
	ctx context.Context,
	session authdomain.Session,
	user userdomain.User,
	sp samldomain.ServiceProvider,
	assertionID string,
	inResponseTo string,
	now time.Time,
) (*etree.Element, error) {
	nameIDFormat := normalizedNameIDFormat(sp.NameIDFormat)
	nameIDValue, err := s.nameIDValue(user, sp.EntityID, nameIDFormat)
	if err != nil {
		return nil, err
	}

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", assertionNS)
	assertion.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	assertion.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	assertion.CreateAttr("ID", assertionID)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", samlTime(now))

	issuer := assertion.CreateElement("saml:Issuer")
	issuer.SetText(s.idpEntityID())

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", nameIDFormat)
	nameID.SetText(nameIDValue)

	subjectConfirmation := subject.CreateElement("saml:SubjectConfirmation")
	subjectConfirmation.CreateAttr("Method", subjectConfirmationBear)
	subjectConfirmationData := subjectConfirmation.CreateElement("saml:SubjectConfirmationData")
	subjectConfirmationData.CreateAttr("Recipient", sp.ACSURL)
	subjectConfirmationData.CreateAttr("NotOnOrAfter", samlTime(now.Add(assertionLifetime)))
	if inResponseTo != "" {
		subjectConfirmationData.CreateAttr("InResponseTo", inResponseTo)
	}

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", samlTime(now.Add(-allowedClockSkew)))
	conditions.CreateAttr("NotOnOrAfter", samlTime(now.Add(assertionLifetime)))
	audienceRestriction := conditions.CreateElement("saml:AudienceRestriction")
	audience := audienceRestriction.CreateElement("saml:Audience")
	audience.SetText(sp.EntityID)

	authnStatement := assertion.CreateElement("saml:AuthnStatement")
	authnStatement.CreateAttr("AuthnInstant", samlTime(now))
	authnStatement.CreateAttr("SessionIndex", session.ID.String())
	authnStatement.CreateAttr("SessionNotOnOrAfter", samlTime(session.ExpiresAt.UTC()))
	authnContext := authnStatement.CreateElement("saml:AuthnContext")
	authnContextClassRef := authnContext.CreateElement("saml:AuthnContextClassRef")
	authnContextClassRef.SetText(authnContextPassword)

	groups, err := s.users.ListGroupCodes(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	attributeStatement := assertion.CreateElement("saml:AttributeStatement")
	addAttribute(attributeStatement, sp.AttributeMapping, "username", user.Username)
	addAttribute(attributeStatement, sp.AttributeMapping, "email", user.Email)
	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		displayName = user.Username
	}
	addAttribute(attributeStatement, sp.AttributeMapping, "name", displayName)
	addMultiValueAttribute(attributeStatement, sp.AttributeMapping, "groups", groups)

	return assertion, nil
}

func (s *Service) signElement(element *etree.Element) (*etree.Element, error) {
	ctx := goxmldsig.NewDefaultSigningContext(goxmldsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{s.certs.Certificate().Raw},
		PrivateKey:  s.certs.PrivateKey(),
	}))
	ctx.Hash = crypto.SHA256
	ctx.Canonicalizer = goxmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(goxmldsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}

	return ctx.SignEnveloped(element)
}

func (s *Service) loadAssertionUser(ctx context.Context, session authdomain.Session, tenantID uuid.UUID) (userdomain.User, error) {
	if s.users == nil {
		return userdomain.User{}, samldomain.ProtocolError{Status: http.StatusInternalServerError, Message: "saml user repository is not configured"}
	}

	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		if errorsIs(err, store.ErrNotFound) {
			return userdomain.User{}, samldomain.ProtocolError{Status: http.StatusUnauthorized, Message: "user no longer exists"}
		}
		return userdomain.User{}, err
	}

	if user.Status != "active" {
		return userdomain.User{}, samldomain.ProtocolError{Status: http.StatusForbidden, Message: "user is not active"}
	}
	if user.TenantID != tenantID {
		return userdomain.User{}, samldomain.ProtocolError{Status: http.StatusForbidden, Message: "user tenant does not match the service provider tenant"}
	}

	return user, nil
}

func (s *Service) nameIDValue(user userdomain.User, entityID, format string) (string, error) {
	switch format {
	case samldomain.DefaultNameIDFormat:
		if strings.TrimSpace(user.Email) == "" {
			return "", samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "user email is required for emailAddress NameID"}
		}
		return strings.TrimSpace(user.Email), nil
	case samldomain.NameIDFormatPersistent:
		secret := strings.TrimSpace(s.sessionSecret)
		if secret == "" {
			return "", samldomain.ProtocolError{Status: http.StatusInternalServerError, Message: "session secret is required for persistent NameID"}
		}

		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(user.TenantID.String()))
		_, _ = mac.Write([]byte(":"))
		_, _ = mac.Write([]byte(user.ID.String()))
		_, _ = mac.Write([]byte(":"))
		_, _ = mac.Write([]byte(entityID))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	case samldomain.NameIDFormatUnspecified:
		return user.Username, nil
	default:
		return "", samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "unsupported NameID format"}
	}
}

func parseSPInitiatedRequest(input samldomain.SPInitiatedRequest) (parsedAuthnRequest, error) {
	input.Binding = strings.TrimSpace(input.Binding)
	input.SAMLRequest = strings.TrimSpace(input.SAMLRequest)
	if input.SAMLRequest == "" {
		return parsedAuthnRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "SAMLRequest is required"}
	}

	requestXML, err := decodeAuthnRequestXML(input.Binding, input.SAMLRequest)
	if err != nil {
		return parsedAuthnRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: err.Error()}
	}

	var envelope authnRequestEnvelope
	if err := xml.Unmarshal(requestXML, &envelope); err != nil {
		return parsedAuthnRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "SAMLRequest must be valid SAML AuthnRequest XML"}
	}
	if envelope.XMLName.Local != "AuthnRequest" {
		return parsedAuthnRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "SAMLRequest root element must be AuthnRequest"}
	}
	if strings.TrimSpace(envelope.ID) == "" {
		return parsedAuthnRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "AuthnRequest ID is required"}
	}
	if strings.TrimSpace(envelope.Issuer.Value) == "" {
		return parsedAuthnRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "AuthnRequest issuer is required"}
	}

	return parsedAuthnRequest{
		ID:           strings.TrimSpace(envelope.ID),
		Issuer:       strings.TrimSpace(envelope.Issuer.Value),
		Destination:  strings.TrimSpace(envelope.Destination),
		ACSURL:       strings.TrimSpace(envelope.AssertionConsumerServiceURL),
		NameIDFormat: strings.TrimSpace(envelope.NameIDPolicy.Format),
		RelayState:   strings.TrimSpace(input.RelayState),
	}, nil
}

func decodeAuthnRequestXML(binding, rawValue string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawValue)
	if err != nil {
		return nil, fmt.Errorf("SAMLRequest must be valid base64")
	}

	if strings.EqualFold(strings.TrimSpace(binding), samldomain.BindingHTTPPost) {
		return decoded, nil
	}

	reader := flate.NewReader(bytes.NewReader(decoded))
	defer reader.Close()

	inflated, err := ioReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("SAMLRequest must be valid DEFLATE data for HTTP-Redirect binding")
	}

	return inflated, nil
}

func normalizedNameIDFormat(raw string) string {
	value := strings.TrimSpace(raw)
	switch value {
	case "", samldomain.DefaultNameIDFormat:
		return samldomain.DefaultNameIDFormat
	case "emailAddress":
		return samldomain.DefaultNameIDFormat
	case samldomain.NameIDFormatPersistent, "persistent":
		return samldomain.NameIDFormatPersistent
	case samldomain.NameIDFormatUnspecified, "unspecified":
		return samldomain.NameIDFormatUnspecified
	default:
		return value
	}
}

func addAttribute(parent *etree.Element, mapping map[string]string, key string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}

	attribute := parent.CreateElement("saml:Attribute")
	attribute.CreateAttr("Name", mappedAttributeName(mapping, key))
	attributeValue := attribute.CreateElement("saml:AttributeValue")
	attributeValue.CreateAttr("xsi:type", "xs:string")
	attributeValue.SetText(value)
}

func addMultiValueAttribute(parent *etree.Element, mapping map[string]string, key string, values []string) {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}
	if len(filtered) == 0 {
		return
	}

	attribute := parent.CreateElement("saml:Attribute")
	attribute.CreateAttr("Name", mappedAttributeName(mapping, key))
	for _, value := range filtered {
		attributeValue := attribute.CreateElement("saml:AttributeValue")
		attributeValue.CreateAttr("xsi:type", "xs:string")
		attributeValue.SetText(value)
	}
}

func mappedAttributeName(mapping map[string]string, key string) string {
	if mapping != nil {
		if value := strings.TrimSpace(mapping[key]); value != "" {
			return value
		}
	}
	return key
}

func samlTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func newSAMLID() string {
	return "_" + uuid.NewString()
}

func protocolErrorFromAPIError(err error) error {
	var protocolErr samldomain.ProtocolError
	if errorsAs(err, &protocolErr) {
		return protocolErr
	}

	return samldomain.ProtocolError{Status: http.StatusBadRequest, Message: err.Error()}
}

type parsedAuthnRequest struct {
	ID           string
	Issuer       string
	Destination  string
	ACSURL       string
	NameIDFormat string
	RelayState   string
}

type authnRequestEnvelope struct {
	XMLName                      xml.Name           `xml:"AuthnRequest"`
	ID                           string             `xml:"ID,attr"`
	Destination                  string             `xml:"Destination,attr"`
	AssertionConsumerServiceURL  string             `xml:"AssertionConsumerServiceURL,attr"`
	Issuer                       issuerElement      `xml:"Issuer"`
	NameIDPolicy                 authnRequestPolicy `xml:"NameIDPolicy"`
}

type issuerElement struct {
	Value string `xml:",chardata"`
}

type authnRequestPolicy struct {
	Format string `xml:"Format,attr"`
}

func errorsAs(err error, target any) bool {
	return errors.As(err, target)
}

func errorsIs(err, target error) bool {
	return errors.Is(err, target)
}

func ioReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
