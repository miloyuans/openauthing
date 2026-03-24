package domain

import (
	"time"

	"github.com/google/uuid"
)

const (
	DefaultNameIDFormat     = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	BindingHTTPPost         = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingHTTPRedirect     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	ProtocolNamespaceSAML20 = "urn:oasis:names:tc:SAML:2.0:protocol"
)

type ServiceProvider struct {
	AppID                 uuid.UUID         `json:"app_id"`
	EntityID              string            `json:"entity_id"`
	ACSURL                string            `json:"acs_url"`
	SLOURL                string            `json:"slo_url"`
	NameIDFormat          string            `json:"nameid_format"`
	WantAssertionsSigned  bool              `json:"want_assertions_signed"`
	WantResponseSigned    bool              `json:"want_response_signed"`
	SignAuthnRequest      bool              `json:"sign_authn_request"`
	EncryptAssertion      bool              `json:"encrypt_assertion"`
	SPMetadataXML         string            `json:"sp_metadata_xml"`
	SPX509Cert            string            `json:"sp_x509_cert"`
	AttributeMapping      map[string]string `json:"attribute_mapping"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

type UpsertServiceProviderInput struct {
	EntityID             string            `json:"entity_id"`
	ACSURL               string            `json:"acs_url"`
	SLOURL               string            `json:"slo_url"`
	NameIDFormat         string            `json:"nameid_format"`
	WantAssertionsSigned bool              `json:"want_assertions_signed"`
	WantResponseSigned   bool              `json:"want_response_signed"`
	SignAuthnRequest     bool              `json:"sign_authn_request"`
	EncryptAssertion     bool              `json:"encrypt_assertion"`
	SPMetadataXML        string            `json:"sp_metadata_xml"`
	SPX509Cert           string            `json:"sp_x509_cert"`
	AttributeMapping     map[string]string `json:"attribute_mapping"`
}
