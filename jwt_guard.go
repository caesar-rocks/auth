package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	caesar "github.com/caesar-rocks/core"
	"github.com/golang-jwt/jwt/v5"
)

// GenerateJWT is a method that generates a JWT token for the user.
func (auth *Auth) GenerateJWT(user any) (string, error) {
	pk := retrievePrimaryKey(user)
	if pk == nil {
		return "", errors.New("primary key not found")
	}

	claims := jwt.MapClaims{
		"user_id": pk,
		"exp":     time.Now().Add(auth.JWTExpiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(auth.JWTSigningKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (auth *Auth) authenticateRequestThroughJWT(ctx *caesar.CaesarCtx, authorizationHeader string) error {
	// Split the authorization header to get the token
	tokenString, err := extractTokenFromHeader(authorizationHeader)
	if err != nil {
		return err
	}

	// Parse and validate the JWT token
	token, err := parseAndValidateToken(tokenString, auth.JWTSigningKey)
	if err != nil {
		return err
	}

	// Extract user ID from the token claims
	userID, err := extractUserIDFromClaims(token.Claims)
	if err != nil {
		return err
	}

	// Retrieve the user and set the context
	return auth.setUserContext(ctx, userID)
}

func extractTokenFromHeader(authorizationHeader string) (string, error) {
	parts := strings.Split(authorizationHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}
	return parts[1], nil
}

func parseAndValidateToken(tokenString string, signingKey any) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return signingKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token, nil
}

func extractUserIDFromClaims(claims jwt.Claims) (any, error) {
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}
	userID, ok := mapClaims["user_id"]
	if !ok {
		return "", errors.New("user_id not found in token claims")
	}
	return userID, nil
}

func (auth *Auth) setUserContext(ctx *caesar.CaesarCtx, userID any) error {
	user, err := auth.UserProvider(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	ctx.Request = ctx.Request.WithContext(
		context.WithValue(ctx.Request.Context(), USER_CONTEXT_KEY, user),
	)
	return nil
}
