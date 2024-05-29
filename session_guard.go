package auth

import (
	"context"
	"errors"

	caesar "github.com/caesar-rocks/core"
)

func (auth *Auth) authenticateRequestThroughSession(ctx *caesar.CaesarCtx) error {
	// Try to retrieve the user ID from the session.
	session, _ := auth.store.Get(ctx.Request, SESSION_NAME)
	userID := session.Values[SESSION_VALUE_KEY]

	if userID == nil {
		return errors.New("user not authenticated")
	}

	user, err := auth.UserProvider(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}

	ctx.Request = ctx.Request.WithContext(
		context.WithValue(ctx.Request.Context(),
			USER_CONTEXT_KEY, user,
		),
	)

	return nil
}
