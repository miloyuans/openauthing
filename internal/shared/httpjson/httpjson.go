package httpjson

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/requestid"
)

type envelope struct {
	RequestID string      `json:"request_id"`
	Data      any         `json:"data,omitempty"`
	Error     *ErrorValue `json:"error,omitempty"`
}

type ErrorValue struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func Write(w http.ResponseWriter, r *http.Request, status int, payload any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	return encoder.Encode(envelope{
		RequestID: requestid.FromContext(r.Context()),
		Data:      payload,
	})
}

func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) error {
	return WriteAPIError(w, r, apierror.New(status, code, message))
}

func WriteAPIError(w http.ResponseWriter, r *http.Request, apiErr apierror.Error) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(apiErr.Status)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	return encoder.Encode(envelope{
		RequestID: requestid.FromContext(r.Context()),
		Error: &ErrorValue{
			Code:    apiErr.Code,
			Message: apiErr.Message,
			Details: apiErr.Details,
		},
	})
}

func WriteErrorFrom(w http.ResponseWriter, r *http.Request, err error) error {
	var apiErr apierror.Error
	if errors.As(err, &apiErr) {
		return WriteAPIError(w, r, apiErr)
	}

	return WriteAPIError(w, r, apierror.Internal())
}
