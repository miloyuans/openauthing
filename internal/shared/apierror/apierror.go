package apierror

import "net/http"

const (
	CodeInternalError   = "internal_error"
	CodeServiceNotReady = "service_not_ready"
	CodeUnauthorized    = "unauthorized"
	CodeForbidden       = "forbidden"
	CodeInvalidConfig   = "invalid_config"
)

type Error struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
}

func New(status int, code, message string) Error {
	return Error{
		Status:  status,
		Code:    code,
		Message: message,
	}
}

func Internal() Error {
	return New(http.StatusInternalServerError, CodeInternalError, "internal server error")
}

func ServiceNotReady() Error {
	return New(http.StatusServiceUnavailable, CodeServiceNotReady, "service dependencies are not ready")
}

func Unauthorized(message string) Error {
	if message == "" {
		message = "authentication is required"
	}

	return New(http.StatusUnauthorized, CodeUnauthorized, message)
}

func Forbidden(message string) Error {
	if message == "" {
		message = "access denied"
	}

	return New(http.StatusForbidden, CodeForbidden, message)
}

func InvalidConfig(message string, details map[string]any) Error {
	err := New(http.StatusInternalServerError, CodeInvalidConfig, message)
	err.Details = details
	return err
}
