package auth

import (
	"context"
	"errors"
	"reflect"
	"strings"

	caesar "github.com/caesar-rocks/core"
	"github.com/gorilla/sessions"
)

const (
	SESSION_NAME      = "caesar_session"
	SESSION_VALUE_KEY = "user_id"
	USER_CONTEXT_KEY  = "user"
)

type Auth struct {
	*AuthCfg
	Social *SocialAuth

	store *sessions.CookieStore
}

type AuthCfg struct {
	Key             string
	MaxAge          int
	IsProd          bool
	SocialProviders *map[string]SocialAuthProvider
	UserProvider    func(ctx context.Context, userID any) (any, error)
	RedirectTo      string
}

func retrievePrimaryKey(model any) any {
	v := reflect.ValueOf(model)

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		value := field.Interface()
		tag := v.Type().Field(i).Tag.Get("bun")

		if strings.Contains(tag, "pk") {
			return value
		}
	}

	return nil
}

// Authenticate is a method that sets the user in the session.
// The session consists in a http.Cookie that is set in the client's browser.
func (a *Auth) Authenticate(ctx *caesar.CaesarCtx, user any) error {
	session, err := a.store.Get(ctx.Request, SESSION_NAME)
	if err != nil {
		return err
	}

	pk := retrievePrimaryKey(user)
	if pk == nil {
		return errors.New("primary key not found")
	}

	session.Values[SESSION_VALUE_KEY] = pk
	err = session.Save(ctx.Request, ctx.ResponseWriter)
	if err != nil {
		return err
	}

	return nil
}

func NewAuth(cfg *AuthCfg) *Auth {
	store := sessions.NewCookieStore([]byte(cfg.Key))
	store.MaxAge(cfg.MaxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = cfg.IsProd

	auth := &Auth{
		AuthCfg: cfg,
		store:   store,
	}

	if *cfg.SocialProviders != nil {
		auth.Social = NewSocialAuth(store, *cfg.SocialProviders)
	}

	return auth
}

func (auth *Auth) AuthenticateRequest(ctx *caesar.CaesarCtx) error {
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

// SilentMiddleware is a middleware that injects the user into the context.
func (auth *Auth) SilentMiddleware(ctx *caesar.CaesarCtx) error {
	auth.AuthenticateRequest(ctx)

	return nil
}

func (auth *Auth) AuthMiddleware(ctx *caesar.CaesarCtx) error {
	err := auth.AuthenticateRequest(ctx)
	if err != nil {
		ctx.Redirect(auth.RedirectTo)
	}

	return nil
}

// RetrieveUserFromCtx is a function that retrieves the user from the context.
func RetrieveUserFromCtx[T any](ctx *caesar.CaesarCtx) (*T, error) {
	ctxValue := ctx.Request.Context().Value(USER_CONTEXT_KEY)
	if ctxValue == nil {
		return nil, errors.New("user not found")
	}
	user, ok := ctxValue.(*T)
	if !ok {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// SignOut is a method that removes the user from the session.
func (auth *Auth) SignOut(ctx *caesar.CaesarCtx) error {
	session, err := auth.store.Get(ctx.Request, SESSION_NAME)
	if err != nil {
		return err
	}

	delete(session.Values, SESSION_VALUE_KEY)
	err = session.Save(ctx.Request, ctx.ResponseWriter)
	if err != nil {
		return err
	}

	return nil
}
