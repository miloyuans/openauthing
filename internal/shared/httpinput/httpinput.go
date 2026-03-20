package httpinput

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/miloyuans/openauthing/internal/shared/apierror"
)

const (
	defaultLimit = 20
	maxLimit     = 100
)

func DecodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return apierror.BadRequest("request body is required", nil)
	}

	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		if err == io.EOF {
			return apierror.BadRequest("request body is required", nil)
		}

		return apierror.BadRequest("request body is invalid JSON", map[string]any{"cause": err.Error()})
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return apierror.BadRequest("request body must contain a single JSON object", nil)
	}

	return nil
}

func ParsePagination(r *http.Request) (int, int, error) {
	limit := defaultLimit
	offset := 0

	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return 0, 0, apierror.BadRequest("limit must be a positive integer", nil)
		}
		if parsed > maxLimit {
			parsed = maxLimit
		}
		limit = parsed
	}

	if raw := r.URL.Query().Get("offset"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return 0, 0, apierror.BadRequest("offset must be zero or a positive integer", nil)
		}
		offset = parsed
	}

	return limit, offset, nil
}
