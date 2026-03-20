package sessionctx

import (
	"context"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
)

type contextKey string

const sessionKey contextKey = "auth_session"

func NewContext(ctx context.Context, session authdomain.Session) context.Context {
	return context.WithValue(ctx, sessionKey, session)
}

func FromContext(ctx context.Context) (authdomain.Session, bool) {
	session, ok := ctx.Value(sessionKey).(authdomain.Session)
	return session, ok
}
