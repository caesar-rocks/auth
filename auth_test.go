package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	caesar "github.com/caesar-rocks/core"
)

type user struct {
	ID string `bun:"id,pk"`
}

func TestRetrievePrimaryKey(t *testing.T) {
	type article struct {
		Identifier int `bun:"id,pk,autoincrement"`
	}

	pk := retrievePrimaryKey(user{ID: "la-jeune-parque"})
	if pk != "la-jeune-parque" {
		t.Errorf("Expected %s, got %s", "la-jeune-parque", pk)
	}

	pk = retrievePrimaryKey(article{Identifier: 123})
	if pk != 123 {
		t.Errorf("Expected %d, got %s", 123, pk)
	}
}

func TestAuthenticateRequest(t *testing.T) {
	user := user{ID: "la-jeune-parque"}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	responseWriter := httptest.NewRecorder()
	ctx := &caesar.CaesarCtx{Request: request, ResponseWriter: responseWriter}

	auth := NewAuth(&AuthCfg{
		JWTSigningKey: []byte("secret"),
		JWTExpiration: time.Hour * 24 * 365,
		UserProvider: func(ctx context.Context, userID any) (any, error) {
			if userID == "la-jeune-parque" {
				return &user, nil
			}
			return nil, nil
		},
	})

	jwt, err := auth.GenerateJWT(user)
	if err != nil {
		t.Error(err)
	}

	request.Header.Set("Authorization", "Bearer "+jwt)
	err = auth.AuthenticateRequest(ctx)
	if err != nil {
		t.Error(err)
	}
}
