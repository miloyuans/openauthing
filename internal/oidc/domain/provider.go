package domain

type DiscoveryDocument struct {
	Issuer                                string   `json:"issuer"`
	AuthorizationEndpoint                 string   `json:"authorization_endpoint"`
	TokenEndpoint                         string   `json:"token_endpoint"`
	UserinfoEndpoint                      string   `json:"userinfo_endpoint"`
	JWKSURI                               string   `json:"jwks_uri"`
	ResponseTypesSupported                []string `json:"response_types_supported"`
	SubjectTypesSupported                 []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported      []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                       []string `json:"scopes_supported"`
	ClaimsSupported                       []string `json:"claims_supported"`
	GrantTypesSupported                   []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported     []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported         []string `json:"code_challenge_methods_supported,omitempty"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KTY string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	KID string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}
