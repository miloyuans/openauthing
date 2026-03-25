package domain

import "net/http"

type SPInitiatedRequest struct {
	Binding       string
	SAMLRequest   string
	RelayState    string
	SigAlg        string
	Signature     string
}

type LogoutRequest struct {
	Binding       string
	SAMLRequest   string
	RelayState    string
	SigAlg        string
	Signature     string
}

type LoginResult struct {
	ACSURL       string
	SAMLResponse string
	RelayState   string
	AppID        string
	EntityID     string
}

type LogoutResult struct {
	SLOURL       string
	SAMLResponse string
	RelayState   string
	AppID        string
	EntityID     string
}

type ProtocolError struct {
	Status  int
	Message string
}

func (e ProtocolError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return http.StatusText(e.Status)
}
