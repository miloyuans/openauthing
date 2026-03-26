package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"

	samlkeys "github.com/miloyuans/openauthing/internal/saml/keys"
)

func TestBuildRedirectRequestURLIncludesAuthnRequestAndRelayState(t *testing.T) {
	cfg := config{
		EntityID:          "http://localhost:8082/metadata",
		ACSURL:            "http://localhost:8082/acs",
		IDPSSOBrowserURL:  "http://localhost:8080/saml/idp/sso",
		DefaultRelayState: "relay-default",
	}

	redirectURL, requestXML, err := buildRedirectRequestURL(cfg, "relay-123", "persistent")
	if err != nil {
		t.Fatalf("build redirect url: %v", err)
	}

	if !strings.Contains(requestXML, `AssertionConsumerServiceURL="http://localhost:8082/acs"`) {
		t.Fatalf("expected ACS URL in AuthnRequest XML, got %s", requestXML)
	}
	if !strings.Contains(requestXML, `Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"`) {
		t.Fatalf("expected persistent NameID format, got %s", requestXML)
	}

	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect url: %v", err)
	}
	if parsed.Scheme != "http" || parsed.Host != "localhost:8080" || parsed.Path != "/saml/idp/sso" {
		t.Fatalf("unexpected redirect target: %s", redirectURL)
	}
	if parsed.Query().Get("RelayState") != "relay-123" {
		t.Fatalf("unexpected relay state: %s", parsed.Query().Get("RelayState"))
	}
	if parsed.Query().Get("SAMLRequest") == "" {
		t.Fatal("expected SAMLRequest query parameter")
	}
}

func TestACSHandlerDisplaysParsedAssertionAndSignatureResult(t *testing.T) {
	metadataXML, samlResponse := signedFixture(t)

	app := newApp(config{
		Addr:                  ":8082",
		BaseURL:               "http://localhost:8082",
		EntityID:              "http://localhost:8082/metadata",
		ACSURL:                "http://localhost:8082/acs",
		SLOURL:                "http://localhost:8082/slo",
		DefaultRelayState:     "relay-default",
		IDPSSOBrowserURL:      "http://localhost:8080/saml/idp/sso",
		IDPMetadataURL:        "http://openauthing:8080/saml/idp/metadata",
		IDPMetadataBrowserURL: "http://localhost:8080/saml/idp/metadata",
	})
	app.metadataFetcher = func(context.Context) ([]byte, error) {
		return []byte(metadataXML), nil
	}

	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	form.Set("RelayState", "relay-local")

	req := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	app.handleACS(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	for _, expected := range []string{
		"Alice Example",
		"alice@example.com",
		"platform",
		"relay-local",
		"signature valid",
		"Assertion",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q in ACS response body: %s", expected, body)
		}
	}
}

func TestMetadataEndpointContainsEntityAndACS(t *testing.T) {
	app := newApp(config{
		EntityID: "http://localhost:8082/metadata",
		ACSURL:   "http://localhost:8082/acs",
		SLOURL:   "http://localhost:8082/slo",
	})

	req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
	recorder := httptest.NewRecorder()
	app.handleMetadata(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	for _, expected := range []string{
		`entityID="http://localhost:8082/metadata"`,
		"http://localhost:8082/acs",
		"AssertionConsumerService",
		"SingleLogoutService",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q in metadata body: %s", expected, body)
		}
	}
}

func signedFixture(t *testing.T) (string, string) {
	t.Helper()

	manager, err := samlkeys.NewManager("http://localhost:8080/saml/idp/metadata", "", "", nil)
	if err != nil {
		t.Fatalf("create key manager: %v", err)
	}

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	assertion.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	assertion.CreateAttr("ID", "_assertion123")
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", "2026-03-26T10:00:00Z")

	issuer := assertion.CreateElement("saml:Issuer")
	issuer.SetText("http://localhost:8080/saml/idp/metadata")

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nameID.SetText("alice@example.com")

	authnStatement := assertion.CreateElement("saml:AuthnStatement")
	authnStatement.CreateAttr("SessionIndex", "session-123")

	attributeStatement := assertion.CreateElement("saml:AttributeStatement")
	addFixtureAttribute(attributeStatement, "username", "alice")
	addFixtureAttribute(attributeStatement, "email", "alice@example.com")
	addFixtureAttribute(attributeStatement, "display_name", "Alice Example")
	addFixtureAttribute(attributeStatement, "groups", "platform")

	signedAssertion := signFixtureElement(t, assertion, manager)

	response := etree.NewElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	response.CreateAttr("xmlns:ds", goxmldsig.Namespace)
	response.CreateAttr("ID", "_response123")
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", "2026-03-26T10:00:00Z")
	response.CreateAttr("Destination", "http://localhost:8082/acs")
	response.CreateAttr("InResponseTo", "_authn123")

	responseIssuer := response.CreateElement("saml:Issuer")
	responseIssuer.SetText("http://localhost:8080/saml/idp/metadata")
	status := response.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	response.AddChild(signedAssertion)

	doc := etree.NewDocument()
	doc.SetRoot(response)
	rawResponse, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize response: %v", err)
	}

	metadata := `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8080/saml/idp/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + base64.StdEncoding.EncodeToString(manager.Certificate().Raw) + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>`

	return metadata, base64.StdEncoding.EncodeToString(rawResponse)
}

func signFixtureElement(t *testing.T, element *etree.Element, manager *samlkeys.Manager) *etree.Element {
	t.Helper()

	context := goxmldsig.NewDefaultSigningContext(goxmldsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{manager.Certificate().Raw},
		PrivateKey:  manager.PrivateKey(),
	}))
	context.Hash = crypto.SHA256
	context.Canonicalizer = goxmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := context.SetSignatureMethod(goxmldsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}

	signed, err := context.SignEnveloped(element)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	return signed
}

func addFixtureAttribute(parent *etree.Element, name string, value string) {
	attribute := parent.CreateElement("saml:Attribute")
	attribute.CreateAttr("Name", name)
	attributeValue := attribute.CreateElement("saml:AttributeValue")
	attributeValue.CreateAttr("xsi:type", "xs:string")
	attributeValue.SetText(value)
}
