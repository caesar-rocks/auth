package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

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
	MaxAge          time.Duration
	JWTSigningKey   []byte
	JWTExpiration   time.Duration
	SocialProviders *map[string]SocialAuthProvider
	UserProvider    func(ctx context.Context, userID any) (any, error)
	RedirectTo      string
}

func retrievePrimaryKey(model any) any {
	v := reflect.ValueOf(model)

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		value := field.Interface()
		tag := v.Type().Field(i).Tag.Get("gorm")

		if strings.Contains(tag, "primaryKey") {
			return value
		}
	}

	return nil
}

// Authenticate is a method that sets the user in the session.
// The session consists in a http.Cookie that is set in the client's browser.
func (a *Auth) Authenticate(ctx *caesar.Context, user any) error {
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
	store.MaxAge(int(cfg.MaxAge))
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = true
	store.Options.SameSite = http.SameSiteLaxMode

	auth := &Auth{
		AuthCfg: cfg,
		store:   store,
	}

	if cfg.SocialProviders != nil {
		auth.Social = NewSocialAuth(store, *cfg.SocialProviders)
	}

	return auth
}

func (auth *Auth) AuthenticateRequest(ctx *caesar.Context) error {
	authorizationHeader := ctx.Request.Header.Get("Authorization")
	if authorizationHeader != "" {
		return auth.authenticateRequestThroughJWT(ctx, authorizationHeader)
	}
	return auth.authenticateRequestThroughSession(ctx)
}

// SilentMiddleware is a middleware that injects the user into the context.
func (auth *Auth) SilentMiddleware(ctx *caesar.Context) error {
	auth.AuthenticateRequest(ctx)
	ctx.Next()
	return nil
}

func (auth *Auth) AuthMiddleware(ctx *caesar.Context) error {
	if err := auth.AuthenticateRequest(ctx); err != nil {
		return ctx.Redirect(auth.RedirectTo)
	}

	ctx.Next()

	return nil
}

// RetrieveUserFromCtx is a function that retrieves the user from the context.
func RetrieveUserFromCtx[T any](ctx *caesar.Context) (*T, error) {
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
func (auth *Auth) SignOut(ctx *caesar.Context) error {
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
