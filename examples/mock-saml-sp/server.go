package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/russellhaering/goxmldsig"

	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
)

const (
	defaultMockSPAddr             = ":8082"
	defaultMockSPBaseURL          = "http://localhost:8082"
	defaultMockSPIDPSSOBrowserURL = "http://localhost:8080/saml/idp/sso"
	defaultMockSPIDPMetadataURL   = "http://openauthing:8080/saml/idp/metadata"
	defaultRelayState             = "mock-saml-sp-demo"
)

var (
	indexTemplate = template.Must(template.New("mock-saml-sp-index").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mock SAML SP</title>
  <style>
    :root { color-scheme: light; }
    body { margin: 0; font-family: "Segoe UI", sans-serif; background: linear-gradient(180deg, #eff6ff 0%, #dbeafe 100%); color: #0f172a; }
    .shell { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
    .card { width: 100%; max-width: 920px; background: rgba(255,255,255,0.96); border-radius: 22px; box-shadow: 0 20px 60px rgba(15, 23, 42, 0.16); padding: 28px; }
    h1 { margin: 0 0 8px; font-size: 30px; }
    p { margin: 0 0 18px; line-height: 1.55; color: #334155; }
    .grid { display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 20px; }
    .panel { background: #f8fafc; border: 1px solid #dbeafe; border-radius: 16px; padding: 18px; }
    .panel h2 { margin: 0 0 12px; font-size: 18px; }
    .kv { display: grid; grid-template-columns: 180px 1fr; gap: 8px 12px; font-size: 14px; }
    .kv strong { color: #1e293b; }
    code { display: inline-block; white-space: pre-wrap; word-break: break-all; color: #0f172a; background: #e2e8f0; border-radius: 8px; padding: 2px 6px; }
    form { display: grid; gap: 12px; }
    label { display: grid; gap: 6px; font-size: 14px; font-weight: 600; color: #1e293b; }
    input, select, button { font: inherit; }
    input, select { border: 1px solid #cbd5e1; border-radius: 12px; padding: 10px 12px; background: white; }
    button { border: 0; border-radius: 12px; padding: 12px 14px; background: #0f172a; color: white; font-weight: 600; cursor: pointer; }
    .hint { margin-top: 12px; font-size: 13px; color: #64748b; }
    .links { margin-top: 16px; display: flex; gap: 14px; flex-wrap: wrap; }
    a { color: #1d4ed8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    @media (max-width: 860px) {
      .grid { grid-template-columns: 1fr; }
      .kv { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <h1>Mock SAML SP</h1>
      <p>Use this page to start an SP-initiated SAML login against <code>openauthing</code>, receive the ACS POST, and inspect the Assertion payload locally.</p>
      <div class="grid">
        <section class="panel">
          <h2>Start SP-Initiated Login</h2>
          <form method="get" action="/login">
            <label>
              RelayState
              <input name="relay_state" value="{{ .DefaultRelayState }}">
            </label>
            <label>
              NameID Format
              <select name="nameid_format">
                {{ range .NameIDFormats }}
                <option value="{{ .Value }}" {{ if .Selected }}selected{{ end }}>{{ .Label }}</option>
                {{ end }}
              </select>
            </label>
            <button type="submit">Generate AuthnRequest and Redirect</button>
          </form>
          <div class="hint">The mock SP uses HTTP-Redirect binding for the outbound AuthnRequest. openauthing returns the SAMLResponse to ACS by HTTP-POST.</div>
          <div class="links">
            <a href="/metadata">View Mock SP Metadata</a>
            <a href="{{ .IDPMetadataBrowserURL }}">View openauthing IdP Metadata</a>
          </div>
        </section>
        <section class="panel">
          <h2>Current Configuration</h2>
          <div class="kv">
            <strong>Mock SP Base URL</strong><code>{{ .BaseURL }}</code>
            <strong>Entity ID</strong><code>{{ .EntityID }}</code>
            <strong>ACS URL</strong><code>{{ .ACSURL }}</code>
            <strong>SLO URL</strong><code>{{ .SLOURL }}</code>
            <strong>IdP SSO URL</strong><code>{{ .IDPSSOBrowserURL }}</code>
            <strong>IdP Metadata URL</strong><code>{{ .IDPMetadataURL }}</code>
          </div>
          <div class="hint">When running this example with Docker Compose, the browser-facing IdP URL stays on <code>localhost</code>, while signature validation inside the mock SP uses the internal metadata URL.</div>
        </section>
      </div>
    </div>
  </div>
</body>
</html>`))
	acsTemplate = template.Must(template.New("mock-saml-sp-acs").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mock SAML SP ACS Result</title>
  <style>
    :root { color-scheme: light; }
    body { margin: 0; font-family: "Segoe UI", sans-serif; background: linear-gradient(180deg, #f8fafc 0%, #e2e8f0 100%); color: #0f172a; }
    .shell { min-height: 100vh; padding: 24px; }
    .wrap { max-width: 1080px; margin: 0 auto; display: grid; gap: 18px; }
    .card { background: rgba(255,255,255,0.98); border-radius: 18px; box-shadow: 0 18px 50px rgba(15, 23, 42, 0.12); padding: 22px; }
    h1, h2 { margin: 0 0 12px; }
    p { margin: 0 0 12px; color: #334155; line-height: 1.55; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
    .kv { display: grid; grid-template-columns: 180px 1fr; gap: 8px 12px; font-size: 14px; }
    .kv strong { color: #1e293b; }
    .badge { display: inline-flex; align-items: center; padding: 5px 10px; border-radius: 999px; font-size: 13px; font-weight: 700; }
    .badge.valid { background: #dcfce7; color: #166534; }
    .badge.invalid { background: #fee2e2; color: #991b1b; }
    .badge.skipped { background: #fef3c7; color: #92400e; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { border-bottom: 1px solid #e2e8f0; padding: 10px 12px; text-align: left; vertical-align: top; }
    th { width: 220px; color: #334155; }
    pre { margin: 0; white-space: pre-wrap; word-break: break-word; background: #0f172a; color: #e2e8f0; border-radius: 14px; padding: 16px; overflow-x: auto; font-size: 13px; }
    .links { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 14px; }
    a { color: #1d4ed8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
      .kv { grid-template-columns: 1fr; }
      th { width: auto; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="wrap">
      <section class="card">
        <h1>ACS Result</h1>
        <p>The mock SP accepted the ACS POST and parsed the SAML Response below.</p>
        <div class="grid">
          <div>
            <div class="kv">
              <strong>RelayState</strong><span>{{ .RelayState }}</span>
              <strong>NameID</strong><span>{{ .NameID }}</span>
              <strong>NameID Format</strong><span>{{ .NameIDFormat }}</span>
              <strong>SessionIndex</strong><span>{{ .SessionIndex }}</span>
              <strong>Response Destination</strong><span>{{ .Destination }}</span>
              <strong>InResponseTo</strong><span>{{ .InResponseTo }}</span>
              <strong>Response Issuer</strong><span>{{ .ResponseIssuer }}</span>
              <strong>Assertion Issuer</strong><span>{{ .AssertionIssuer }}</span>
            </div>
          </div>
          <div>
            <div style="margin-bottom: 10px;"><strong>Signature Validation</strong></div>
            <div class="badge {{ .SignatureCSSClass }}">{{ .SignatureStatus }}</div>
            <p style="margin-top: 12px;">{{ .SignatureDetail }}</p>
          </div>
        </div>
        <div class="links">
          <a href="/">Start another login</a>
          <a href="/metadata">View Mock SP Metadata</a>
        </div>
      </section>

      <section class="card">
        <h2>Assertion Attributes</h2>
        {{ if .Attributes }}
        <table>
          <thead>
            <tr><th>Attribute</th><th>Values</th></tr>
          </thead>
          <tbody>
            {{ range .Attributes }}
            <tr>
              <th>{{ .Name }}</th>
              <td>{{ range $i, $value := .Values }}{{ if $i }}, {{ end }}{{ $value }}{{ end }}</td>
            </tr>
            {{ end }}
          </tbody>
        </table>
        {{ else }}
        <p>No attributes were found in the Assertion.</p>
        {{ end }}
      </section>

      <section class="card">
        <h2>Decoded SAML Response XML</h2>
        <pre>{{ .ResponseXML }}</pre>
      </section>

      <section class="card">
        <h2>Decoded Assertion XML</h2>
        <pre>{{ .AssertionXML }}</pre>
      </section>
    </div>
  </div>
</body>
</html>`))
)

type config struct {
	Addr                  string
	BaseURL               string
	EntityID              string
	ACSURL                string
	SLOURL                string
	DefaultRelayState     string
	IDPSSOBrowserURL      string
	IDPMetadataURL        string
	IDPMetadataBrowserURL string
}

type app struct {
	cfg             config
	httpClient      *http.Client
	metadataFetcher func(ctx context.Context) ([]byte, error)
}

type indexPageData struct {
	BaseURL               string
	EntityID              string
	ACSURL                string
	SLOURL                string
	DefaultRelayState     string
	IDPSSOBrowserURL      string
	IDPMetadataURL        string
	IDPMetadataBrowserURL string
	NameIDFormats         []nameIDFormatOption
}

type nameIDFormatOption struct {
	Label    string
	Value    string
	Selected bool
}

type acsPageData struct {
	RelayState        string
	NameID            string
	NameIDFormat      string
	SessionIndex      string
	Destination       string
	InResponseTo      string
	ResponseIssuer    string
	AssertionIssuer   string
	Attributes        []attributeValue
	SignatureStatus   string
	SignatureDetail   string
	SignatureCSSClass string
	ResponseXML       string
	AssertionXML      string
}

type attributeValue struct {
	Name   string
	Values []string
}

type parsedResponse struct {
	RelayState      string
	NameID          string
	NameIDFormat    string
	SessionIndex    string
	Destination     string
	InResponseTo    string
	ResponseIssuer  string
	AssertionIssuer string
	Attributes      []attributeValue
	ResponseXML     string
	AssertionXML    string
}

type signatureCheck struct {
	Status   string
	Detail   string
	CSSClass string
}

func loadConfig() config {
	baseURL := envOrDefault("MOCK_SAML_SP_BASE_URL", defaultMockSPBaseURL)
	addr := envOrDefault("MOCK_SAML_SP_ADDR", defaultMockSPAddr)
	entityID := strings.TrimSpace(os.Getenv("MOCK_SAML_SP_ENTITY_ID"))
	if entityID == "" {
		entityID = strings.TrimRight(baseURL, "/") + "/metadata"
	}
	acsURL := strings.TrimSpace(os.Getenv("MOCK_SAML_SP_ACS_URL"))
	if acsURL == "" {
		acsURL = strings.TrimRight(baseURL, "/") + "/acs"
	}
	sloURL := strings.TrimSpace(os.Getenv("MOCK_SAML_SP_SLO_URL"))
	if sloURL == "" {
		sloURL = strings.TrimRight(baseURL, "/") + "/slo"
	}

	idpSSO := envOrDefault("MOCK_SAML_SP_IDP_SSO_URL", defaultMockSPIDPSSOBrowserURL)
	idpMetadata := envOrDefault("MOCK_SAML_SP_IDP_METADATA_URL", defaultMockSPIDPMetadataURL)
	idpMetadataBrowser := strings.TrimSpace(os.Getenv("MOCK_SAML_SP_IDP_METADATA_BROWSER_URL"))
	if idpMetadataBrowser == "" {
		idpMetadataBrowser = strings.TrimRight(idpSSO, "/")
		idpMetadataBrowser = strings.TrimSuffix(idpMetadataBrowser, "/sso") + "/metadata"
	}

	return config{
		Addr:                  addr,
		BaseURL:               baseURL,
		EntityID:              entityID,
		ACSURL:                acsURL,
		SLOURL:                sloURL,
		DefaultRelayState:     envOrDefault("MOCK_SAML_SP_DEFAULT_RELAY_STATE", defaultRelayState),
		IDPSSOBrowserURL:      idpSSO,
		IDPMetadataURL:        idpMetadata,
		IDPMetadataBrowserURL: idpMetadataBrowser,
	}
}

func newApp(cfg config) *app {
	instance := &app{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	instance.metadataFetcher = instance.fetchMetadata
	return instance
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/acs", a.handleACS)
	mux.HandleFunc("/metadata", a.handleMetadata)
	mux.HandleFunc("/healthz", a.handleHealthz)
	return mux
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = indexTemplate.Execute(w, indexPageData{
		BaseURL:               a.cfg.BaseURL,
		EntityID:              a.cfg.EntityID,
		ACSURL:                a.cfg.ACSURL,
		SLOURL:                a.cfg.SLOURL,
		DefaultRelayState:     a.cfg.DefaultRelayState,
		IDPSSOBrowserURL:      a.cfg.IDPSSOBrowserURL,
		IDPMetadataURL:        a.cfg.IDPMetadataURL,
		IDPMetadataBrowserURL: a.cfg.IDPMetadataBrowserURL,
		NameIDFormats: []nameIDFormatOption{
			{Label: "emailAddress", Value: samldomain.DefaultNameIDFormat, Selected: true},
			{Label: "persistent", Value: samldomain.NameIDFormatPersistent},
			{Label: "unspecified", Value: samldomain.NameIDFormatUnspecified},
		},
	})
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	redirectURL, _, err := buildRedirectRequestURL(a.cfg, strings.TrimSpace(r.URL.Query().Get("relay_state")), normalizedNameIDFormat(r.URL.Query().Get("nameid_format")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (a *app) handleACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "acs requires HTTP POST", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "request must be valid form data", http.StatusBadRequest)
		return
	}

	rawResponse := strings.TrimSpace(r.FormValue("SAMLResponse"))
	if rawResponse == "" {
		http.Error(w, "SAMLResponse is required", http.StatusBadRequest)
		return
	}

	result, responseBytes, err := parseSAMLResponse(rawResponse, strings.TrimSpace(r.FormValue("RelayState")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signatureResult := a.verifySignature(r.Context(), responseBytes)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = acsTemplate.Execute(w, acsPageData{
		RelayState:        result.RelayState,
		NameID:            result.NameID,
		NameIDFormat:      result.NameIDFormat,
		SessionIndex:      result.SessionIndex,
		Destination:       result.Destination,
		InResponseTo:      result.InResponseTo,
		ResponseIssuer:    result.ResponseIssuer,
		AssertionIssuer:   result.AssertionIssuer,
		Attributes:        result.Attributes,
		SignatureStatus:   signatureResult.Status,
		SignatureDetail:   signatureResult.Detail,
		SignatureCSSClass: signatureResult.CSSClass,
		ResponseXML:       result.ResponseXML,
		AssertionXML:      result.AssertionXML,
	})
}

func (a *app) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, buildMetadataXML(a.cfg))
}

func (a *app) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (a *app) fetchMetadata(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.IDPMetadataURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch IdP metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch IdP metadata: unexpected status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func (a *app) verifySignature(ctx context.Context, responseXML []byte) signatureCheck {
	metadataXML, err := a.metadataFetcher(ctx)
	if err != nil {
		return signatureCheck{
			Status:   "verification skipped",
			Detail:   fmt.Sprintf("Unable to load IdP metadata: %v", err),
			CSSClass: "skipped",
		}
	}

	certificate, err := extractCertificateFromMetadata(metadataXML)
	if err != nil {
		return signatureCheck{
			Status:   "verification skipped",
			Detail:   fmt.Sprintf("Unable to load signing certificate from metadata: %v", err),
			CSSClass: "skipped",
		}
	}

	target, _, validateErr := validateResponseSignature(responseXML, certificate)
	if validateErr != nil {
		return signatureCheck{
			Status:   "signature invalid",
			Detail:   validateErr.Error(),
			CSSClass: "invalid",
		}
	}

	return signatureCheck{
		Status:   "signature valid",
		Detail:   detailForSignature(target),
		CSSClass: "valid",
	}
}

func buildRedirectRequestURL(cfg config, relayState string, nameIDFormat string) (string, string, error) {
	if relayState == "" {
		relayState = cfg.DefaultRelayState
	}

	requestXML := buildAuthnRequestXML(cfg, nameIDFormat)
	deflated, err := deflateAndEncode([]byte(requestXML))
	if err != nil {
		return "", "", err
	}

	query := url.Values{}
	query.Set("SAMLRequest", deflated)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}

	return strings.TrimRight(cfg.IDPSSOBrowserURL, "?") + "?" + query.Encode(), requestXML, nil
}

func buildAuthnRequestXML(cfg config, nameIDFormat string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="%s" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s">
  <saml:Issuer xmlns:saml="%s">%s</saml:Issuer>
  <samlp:NameIDPolicy Format="%s" AllowCreate="true"/>
</samlp:AuthnRequest>`,
		samldomain.ProtocolNamespaceSAML20,
		"_"+uuid.NewString(),
		time.Now().UTC().Format(time.RFC3339),
		xmlEscape(cfg.IDPSSOBrowserURL),
		xmlEscape(cfg.ACSURL),
		"urn:oasis:names:tc:SAML:2.0:assertion",
		xmlEscape(cfg.EntityID),
		xmlEscape(nameIDFormat),
	)
}

func buildMetadataXML(cfg config) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <SPSSODescriptor protocolSupportEnumeration="%s" AuthnRequestsSigned="false" WantAssertionsSigned="true">
    <NameIDFormat>%s</NameIDFormat>
    <AssertionConsumerService Binding="%s" Location="%s" index="0"/>
    <SingleLogoutService Binding="%s" Location="%s"/>
  </SPSSODescriptor>
</EntityDescriptor>`,
		xmlEscape(cfg.EntityID),
		samldomain.ProtocolNamespaceSAML20,
		samldomain.DefaultNameIDFormat,
		samldomain.BindingHTTPPost,
		xmlEscape(cfg.ACSURL),
		samldomain.BindingHTTPRedirect,
		xmlEscape(cfg.SLOURL),
	)
}

func parseSAMLResponse(rawValue string, relayState string) (parsedResponse, []byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rawValue))
	if err != nil {
		return parsedResponse{}, nil, errors.New("SAMLResponse must be valid base64")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(decoded); err != nil {
		return parsedResponse{}, nil, errors.New("SAMLResponse must be valid XML")
	}

	response := doc.Root()
	if response == nil || localName(response.Tag) != "Response" {
		return parsedResponse{}, nil, errors.New("SAMLResponse root element must be Response")
	}

	assertion := findFirstElementByLocalName(response, "Assertion")
	if assertion == nil {
		return parsedResponse{}, nil, errors.New("SAMLResponse must contain an Assertion")
	}

	result := parsedResponse{
		RelayState:      relayState,
		Destination:     strings.TrimSpace(response.SelectAttrValue("Destination", "")),
		InResponseTo:    strings.TrimSpace(response.SelectAttrValue("InResponseTo", "")),
		ResponseIssuer:  elementText(findFirstElementByLocalName(response, "Issuer")),
		AssertionIssuer: elementText(findFirstElementByLocalName(assertion, "Issuer")),
		NameID:          elementText(findFirstElementByLocalName(assertion, "NameID")),
		ResponseXML:     prettyXML(decoded),
		AssertionXML:    prettyElementXML(assertion),
	}

	if nameID := findFirstElementByLocalName(assertion, "NameID"); nameID != nil {
		result.NameIDFormat = strings.TrimSpace(nameID.SelectAttrValue("Format", ""))
	}
	if authnStatement := findFirstElementByLocalName(assertion, "AuthnStatement"); authnStatement != nil {
		result.SessionIndex = strings.TrimSpace(authnStatement.SelectAttrValue("SessionIndex", ""))
	}
	result.Attributes = collectAttributes(assertion)

	return result, decoded, nil
}

func validateResponseSignature(responseXML []byte, certificate *x509.Certificate) (string, string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(responseXML); err != nil {
		return "", "", fmt.Errorf("parse SAMLResponse XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return "", "", errors.New("SAMLResponse XML is empty")
	}

	validator := goxmldsig.NewDefaultValidationContext(&goxmldsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{certificate},
	})

	candidates := []struct {
		Name    string
		Element *etree.Element
	}{
		{Name: "Response", Element: root},
		{Name: "Assertion", Element: findFirstElementByLocalName(root, "Assertion")},
	}

	var (
		foundSignature bool
		lastErr        error
	)

	for _, candidate := range candidates {
		if candidate.Element == nil || !hasImmediateSignature(candidate.Element) {
			continue
		}
		foundSignature = true
		if _, err := validator.Validate(candidate.Element.Copy()); err == nil {
			return candidate.Name, candidate.Name + " signature validated successfully against IdP metadata certificate", nil
		} else {
			lastErr = err
		}
	}

	if !foundSignature {
		return "", "", errors.New("no Response or Assertion signature was found in the SAMLResponse")
	}
	if lastErr != nil {
		return "", "", fmt.Errorf("XML signature validation failed: %w", lastErr)
	}
	return "", "", errors.New("XML signature validation failed")
}

func extractCertificateFromMetadata(metadataXML []byte) (*x509.Certificate, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(metadataXML); err != nil {
		return nil, err
	}

	certElement := findFirstElementByLocalName(doc.Root(), "X509Certificate")
	if certElement == nil {
		return nil, errors.New("X509Certificate element not found")
	}

	normalized := strings.Join(strings.Fields(certElement.Text()), "")
	if normalized == "" {
		return nil, errors.New("X509Certificate value is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("decode X509Certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil, fmt.Errorf("parse X509Certificate: %w", err)
	}

	return certificate, nil
}

func collectAttributes(assertion *etree.Element) []attributeValue {
	statement := findFirstElementByLocalName(assertion, "AttributeStatement")
	if statement == nil {
		return nil
	}

	attributes := make([]attributeValue, 0)
	for _, attribute := range statement.ChildElements() {
		if localName(attribute.Tag) != "Attribute" {
			continue
		}

		item := attributeValue{Name: strings.TrimSpace(attribute.SelectAttrValue("Name", ""))}
		for _, child := range attribute.ChildElements() {
			if localName(child.Tag) == "AttributeValue" {
				if value := strings.TrimSpace(child.Text()); value != "" {
					item.Values = append(item.Values, value)
				}
			}
		}
		attributes = append(attributes, item)
	}

	return attributes
}

func findFirstElementByLocalName(root *etree.Element, name string) *etree.Element {
	if root == nil {
		return nil
	}
	if localName(root.Tag) == name {
		return root
	}
	for _, child := range root.ChildElements() {
		if found := findFirstElementByLocalName(child, name); found != nil {
			return found
		}
	}
	return nil
}

func hasImmediateSignature(element *etree.Element) bool {
	for _, child := range element.ChildElements() {
		if localName(child.Tag) == "Signature" {
			return true
		}
	}
	return false
}

func localName(tag string) string {
	if index := strings.Index(tag, ":"); index >= 0 {
		return tag[index+1:]
	}
	return tag
}

func elementText(element *etree.Element) string {
	if element == nil {
		return ""
	}
	return strings.TrimSpace(element.Text())
}

func prettyXML(raw []byte) string {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return string(raw)
	}
	doc.Indent(2)
	serialized, err := doc.WriteToString()
	if err != nil {
		return string(raw)
	}
	return serialized
}

func prettyElementXML(element *etree.Element) string {
	if element == nil {
		return ""
	}

	doc := etree.NewDocument()
	doc.SetRoot(element.Copy())
	doc.Indent(2)
	serialized, err := doc.WriteToString()
	if err != nil {
		return ""
	}
	return serialized
}

func normalizedNameIDFormat(raw string) string {
	switch strings.TrimSpace(raw) {
	case "", samldomain.DefaultNameIDFormat:
		return samldomain.DefaultNameIDFormat
	case "emailAddress":
		return samldomain.DefaultNameIDFormat
	case "persistent", samldomain.NameIDFormatPersistent:
		return samldomain.NameIDFormatPersistent
	case "unspecified", samldomain.NameIDFormatUnspecified:
		return samldomain.NameIDFormatUnspecified
	default:
		return samldomain.DefaultNameIDFormat
	}
}

func deflateAndEncode(raw []byte) (string, error) {
	var buffer bytes.Buffer

	writer, err := flate.NewWriter(&buffer, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write(raw); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buffer.Bytes()), nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func xmlEscape(raw string) string {
	var buffer bytes.Buffer
	_ = xml.EscapeText(&buffer, []byte(raw))
	return buffer.String()
}

func detailForSignature(target string) string {
	switch target {
	case "Response":
		return "The mock SP found a ds:Signature on the SAML Response and validated it with the certificate from openauthing IdP metadata."
	case "Assertion":
		return "The mock SP found a ds:Signature on the Assertion and validated it with the certificate from openauthing IdP metadata."
	default:
		return "The mock SP validated the XML signature with the certificate from openauthing IdP metadata."
	}
}
