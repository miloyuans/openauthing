package validate

import (
	"net/mail"
	"net/url"
	"regexp"
	"strings"
)

var (
	usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$`)
	codePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$`)
	phonePattern    = regexp.MustCompile(`^[0-9+() -]{0,32}$`)
)

func Required(field, value string, errs map[string]string) {
	if strings.TrimSpace(value) == "" {
		errs[field] = "is required"
	}
}

func Username(field, value string, errs map[string]string) {
	if strings.TrimSpace(value) == "" {
		errs[field] = "is required"
		return
	}

	if !usernamePattern.MatchString(value) {
		errs[field] = "must be 3-64 chars and contain only letters, numbers, dot, underscore or dash"
	}
}

func Code(field, value string, errs map[string]string) {
	if strings.TrimSpace(value) == "" {
		errs[field] = "is required"
		return
	}

	if !codePattern.MatchString(value) {
		errs[field] = "must be 2-64 chars and contain only letters, numbers, underscore or dash"
	}
}

func Email(field, value string, errs map[string]string) {
	if strings.TrimSpace(value) == "" {
		return
	}

	if _, err := mail.ParseAddress(value); err != nil {
		errs[field] = "must be a valid email address"
	}
}

func Phone(field, value string, errs map[string]string) {
	if strings.TrimSpace(value) == "" {
		return
	}

	if !phonePattern.MatchString(value) {
		errs[field] = "must be a valid phone number"
	}
}

func URL(field, value string, errs map[string]string) {
	if strings.TrimSpace(value) == "" {
		return
	}

	if _, err := url.ParseRequestURI(value); err != nil {
		errs[field] = "must be a valid URL"
	}
}

func OneOf(field, value string, allowed []string, errs map[string]string) {
	if strings.TrimSpace(value) == "" {
		errs[field] = "is required"
		return
	}

	for _, candidate := range allowed {
		if value == candidate {
			return
		}
	}

	errs[field] = "contains an unsupported value"
}
