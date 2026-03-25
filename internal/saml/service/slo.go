package service

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/shared/requestid"

	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
	"github.com/miloyuans/openauthing/internal/store"
)

func (s *Service) HandleLogoutRequest(ctx context.Context, input samldomain.LogoutRequest) (samldomain.LogoutResult, error) {
	request, err := parseLogoutRequest(input)
	if err != nil {
		return samldomain.LogoutResult{}, err
	}

	sp, err := s.repo.GetByEntityID(ctx, request.Issuer)
	if err != nil {
		if errorsIs(err, store.ErrNotFound) {
			return samldomain.LogoutResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "unknown service provider issuer"}
		}
		return samldomain.LogoutResult{}, err
	}
	sp = normalizeServiceProvider(sp)

	if request.Destination != "" && request.Destination != s.endpoint("/saml/idp/slo") {
		return samldomain.LogoutResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "logout request destination does not match the IdP SLO endpoint"}
	}
	if strings.TrimSpace(sp.SLOURL) == "" {
		return samldomain.LogoutResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "service provider does not have a registered SLO URL"}
	}

	loginSession, err := s.lookupActiveLoginSession(ctx, sp.AppID, request.SessionIndex, request.NameID)
	if err != nil {
		return samldomain.LogoutResult{}, err
	}

	now := s.now().UTC()
	if !now.Before(loginSession.ExpiresAt) {
		return samldomain.LogoutResult{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "saml login session has expired"}
	}

	if err := s.withinTx(ctx, func(txCtx context.Context) error {
		if s.sessions != nil {
			if logoutErr := s.sessions.Logout(txCtx, loginSession.SessionID, now); logoutErr != nil && !errorsIs(logoutErr, store.ErrNotFound) {
				return logoutErr
			}
		}

		if s.loginSessions != nil {
			if invalidateErr := s.loginSessions.InvalidateBySessionID(txCtx, loginSession.SessionID, now); invalidateErr != nil && !errorsIs(invalidateErr, store.ErrNotFound) {
				return invalidateErr
			}
		}

		if s.logoutAdapter != nil {
			if hookErr := s.logoutAdapter.OnSessionLoggedOut(txCtx, loginSession.SessionID); hookErr != nil {
				return hookErr
			}
		}

		return nil
	}); err != nil {
		return samldomain.LogoutResult{}, err
	}

	responseXML, err := s.buildLogoutResponse(sp, request.ID)
	if err != nil {
		return samldomain.LogoutResult{}, err
	}

	s.logger.Info("saml slo completed",
		"request_id", requestid.FromContext(ctx),
		"app_id", sp.AppID.String(),
		"sp_entity_id", sp.EntityID,
		"session_id", loginSession.SessionID.String(),
		"user_id", loginSession.UserID.String(),
	)

	return samldomain.LogoutResult{
		SLOURL:       sp.SLOURL,
		SAMLResponse: base64.StdEncoding.EncodeToString(responseXML),
		RelayState:   request.RelayState,
		AppID:        sp.AppID.String(),
		EntityID:     sp.EntityID,
	}, nil
}

func (s *Service) lookupActiveLoginSession(ctx context.Context, appID uuid.UUID, sessionIndex, nameID string) (samldomain.LoginSession, error) {
	if s.loginSessions == nil {
		return samldomain.LoginSession{}, samldomain.ProtocolError{Status: http.StatusInternalServerError, Message: "saml login session repository is not configured"}
	}

	if sessionIndex != "" {
		session, err := s.loginSessions.GetActiveByAppAndSessionIndex(ctx, appID, sessionIndex)
		if err == nil {
			if nameID != "" && !strings.EqualFold(strings.TrimSpace(session.NameID), strings.TrimSpace(nameID)) {
				return samldomain.LoginSession{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "logout request name_id does not match the bound session"}
			}
			return session, nil
		}
		if !errorsIs(err, store.ErrNotFound) {
			return samldomain.LoginSession{}, err
		}
	}

	if nameID != "" {
		session, err := s.loginSessions.GetActiveByAppAndNameID(ctx, appID, nameID)
		if err == nil {
			return session, nil
		}
		if !errorsIs(err, store.ErrNotFound) {
			return samldomain.LoginSession{}, err
		}
	}

	return samldomain.LoginSession{}, samldomain.ProtocolError{Status: http.StatusNotFound, Message: "bound saml login session not found"}
}

func (s *Service) buildLogoutResponse(sp samldomain.ServiceProvider, inResponseTo string) ([]byte, error) {
	response := etree.NewElement("samlp:LogoutResponse")
	response.CreateAttr("xmlns:samlp", samldomain.ProtocolNamespaceSAML20)
	response.CreateAttr("xmlns:saml", assertionNS)
	response.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	response.CreateAttr("ID", newSAMLID())
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", samlTime(s.now().UTC()))
	response.CreateAttr("Destination", sp.SLOURL)
	if inResponseTo != "" {
		response.CreateAttr("InResponseTo", inResponseTo)
	}

	issuer := response.CreateElement("saml:Issuer")
	issuer.SetText(s.idpEntityID())

	status := response.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", samlStatusSuccess)

	signed, err := s.signElement(response)
	if err != nil {
		return nil, fmt.Errorf("sign saml logout response: %w", err)
	}

	document := etree.NewDocument()
	document.WriteSettings = etree.WriteSettings{CanonicalText: true}
	document.SetRoot(signed)
	raw, err := document.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize saml logout response: %w", err)
	}

	return raw, nil
}

func parseLogoutRequest(input samldomain.LogoutRequest) (parsedLogoutRequest, error) {
	input.Binding = strings.TrimSpace(input.Binding)
	input.SAMLRequest = strings.TrimSpace(input.SAMLRequest)
	if input.SAMLRequest == "" {
		return parsedLogoutRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "SAMLRequest is required"}
	}

	requestXML, err := decodeAuthnRequestXML(input.Binding, input.SAMLRequest)
	if err != nil {
		return parsedLogoutRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: err.Error()}
	}

	var envelope logoutRequestEnvelope
	if err := xml.Unmarshal(requestXML, &envelope); err != nil {
		return parsedLogoutRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "SAMLRequest must be valid SAML LogoutRequest XML"}
	}
	if envelope.XMLName.Local != "LogoutRequest" {
		return parsedLogoutRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "SAMLRequest root element must be LogoutRequest"}
	}
	if strings.TrimSpace(envelope.ID) == "" {
		return parsedLogoutRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "LogoutRequest ID is required"}
	}
	if strings.TrimSpace(envelope.Issuer.Value) == "" {
		return parsedLogoutRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "LogoutRequest issuer is required"}
	}
	if strings.TrimSpace(envelope.NameID.Value) == "" && strings.TrimSpace(envelope.SessionIndex) == "" {
		return parsedLogoutRequest{}, samldomain.ProtocolError{Status: http.StatusBadRequest, Message: "LogoutRequest must contain session_index or name_id"}
	}

	return parsedLogoutRequest{
		ID:           strings.TrimSpace(envelope.ID),
		Issuer:       strings.TrimSpace(envelope.Issuer.Value),
		Destination:  strings.TrimSpace(envelope.Destination),
		NameID:       strings.TrimSpace(envelope.NameID.Value),
		SessionIndex: strings.TrimSpace(envelope.SessionIndex),
		RelayState:   strings.TrimSpace(input.RelayState),
	}, nil
}

type parsedLogoutRequest struct {
	ID           string
	Issuer       string
	Destination  string
	NameID       string
	SessionIndex string
	RelayState   string
}

type logoutRequestEnvelope struct {
	XMLName      xml.Name      `xml:"LogoutRequest"`
	ID           string        `xml:"ID,attr"`
	Destination  string        `xml:"Destination,attr"`
	Issuer       issuerElement `xml:"Issuer"`
	NameID       issuerElement `xml:"NameID"`
	SessionIndex string        `xml:"SessionIndex"`
}
