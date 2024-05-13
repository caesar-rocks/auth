package auth

import (
	"context"
	"net/http"

	"github.com/caesar-rocks/core"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

type SocialAuthProvider struct {
	name        string
	Key         string
	Secret      string
	CallbackURL string
	Scopes      []string
}

type SocialAuth struct {
	Providers map[string]SocialAuthProvider
}

func NewSocialAuth(store *sessions.CookieStore, providers map[string]SocialAuthProvider) *SocialAuth {
	gothic.Store = store

	var gothProviders []goth.Provider

	for name, provider := range providers {
		switch name {
		case "github":
			gothProviders = append(
				gothProviders,
				github.New(provider.Key, provider.Secret, provider.CallbackURL, provider.Scopes...),
			)
		case "google":
			gothProviders = append(
				gothProviders,
				google.New(provider.Key, provider.Secret, provider.CallbackURL, provider.Scopes...),
			)
		case "facebook":
			gothProviders = append(
				gothProviders,
				facebook.New(provider.Key, provider.Secret, provider.CallbackURL, provider.Scopes...),
			)
		}
	}

	goth.UseProviders(
		gothProviders...,
	)

	return &SocialAuth{
		Providers: providers,
	}
}

func (s *SocialAuth) Use(provider string) *SocialAuthProvider {
	if p, ok := s.Providers[provider]; ok {
		p.name = provider
		return &p
	}
	return nil
}

func (p *SocialAuthProvider) Redirect(ctx *core.CaesarCtx) error {
	r := ctx.Request.WithContext(
		context.WithValue(
			ctx.Request.Context(),
			"provider", p.name,
		),
	)

	// Handle HTMX requests
	if ctx.GetHeader("HX-Request") == "true" {
		url, err := gothic.GetAuthURL(ctx.ResponseWriter, r)
		if err != nil {
			return err
		}
		ctx.WithStatus(http.StatusSeeOther).SetHeader("HX-Redirect", url)
		return nil
	}

	gothic.BeginAuthHandler(ctx.ResponseWriter, r)

	return nil
}

func (p *SocialAuthProvider) Callback(ctx *core.CaesarCtx) (*goth.User, error) {
	r := ctx.Request.WithContext(
		context.WithValue(
			ctx.Request.Context(),
			"provider", p.name,
		),
	)
	user, err := gothic.CompleteUserAuth(ctx.ResponseWriter, r)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
