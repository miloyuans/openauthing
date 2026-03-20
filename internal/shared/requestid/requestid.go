package requestid

import "context"

type contextKey string

const key contextKey = "request_id"

func NewContext(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, key, value)
}

func FromContext(ctx context.Context) string {
	value, ok := ctx.Value(key).(string)
	if !ok {
		return ""
	}

	return value
}
