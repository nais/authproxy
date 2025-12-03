package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func TestJWTAuthorized(t *testing.T) {
	url := "http://localhost:1234"
	cache, jwks := jwksCache(url)

	jwtProvider, err := JWT("Authorization", url, map[string]any{
		"iss": "http://localhost:1234",
		"aud": "yolo",
	})
	assert.NoError(t, err)
	jwtProvider = jwtProvider.WithJWKSCache(cache)

	provider, err := testProvider(jwtProvider)
	assert.NoError(t, err)

	now := time.Now()
	t1, err := token(now, 60*time.Minute).with("iss", "http://localhost:1234").with("aud", "yolo").sign(jwks)
	assert.NoError(t, err)
	r1, err := provider.withRequest("Authorization", "Bearer "+t1)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, r1.Code)
}

func TestJWTUnauthorized(t *testing.T) {
	url := "http://localhost:1234"
	cache, jwks := jwksCache(url)

	jwtProvider, err := JWT("Authorization", url, map[string]any{
		"iss": "theissuer",
		"aud": "audience",
	})
	assert.NoError(t, err)
	jwtProvider = jwtProvider.WithJWKSCache(cache)

	provider, err := testProvider(jwtProvider)

	assert.NoError(t, err)
	tests := []struct {
		name       string
		tokenFunc  func(t *testing.T) string
		headerName string
	}{
		{
			name:      "missing token",
			tokenFunc: func(t *testing.T) string { return "" },
		},
		{
			name: "sig does not match",
			tokenFunc: func(t *testing.T) string {
				jwks, err := newJwkSet("1234")
				assert.NoError(t, err)

				token, err := token(time.Now(), 1*time.Hour).with("iss", "theissuer").with("aud", "audience").sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "token expired",
			tokenFunc: func(t *testing.T) string {
				iat := time.Now().Add(-5 * time.Second)
				token, err := token(iat, -1*time.Second).with("iss", "theissuer").with("aud", "audience").sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "token is in the future",
			tokenFunc: func(t *testing.T) string {
				iat := time.Now().Add(40 * time.Second)
				token, err := token(iat, 1*time.Minute).with("iss", "theissuer").with("aud", "audience").sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "invalid audience",
			tokenFunc: func(t *testing.T) string {
				token, err := token(time.Now(), 1*time.Hour).with("iss", "theissuer").with("aud", "invalid").sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "invalid issuer",
			tokenFunc: func(t *testing.T) string {
				token, err := token(time.Now(), 1*time.Hour).with("aud", "audience").with("iss", "invalid").sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t1 := tt.tokenFunc(t)
			header := tt.headerName
			if header == "" {
				header = "Authorization"
			}
			r1, err := provider.withRequest(header, t1)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, r1.Code)
			println(r1.Body.String())
		})
	}
}

func jwksCache(url string) (*jwk.Cache, jwk.Set) {
	ctx := context.Background()
	jwks, err := newJwkSet("1234")
	if err != nil {
		panic(err)
	}
	cache := jwk.NewCache(ctx)

	err = cache.Register(url, jwk.WithHTTPClient(httpClient(jwks)))
	if err != nil {
		panic(fmt.Errorf("registering jwks provider uri to cache: %w", err))
	}

	// trigger initial fetch and cache of jwk set
	_, err = cache.Refresh(ctx, url)
	if err != nil {
		panic(fmt.Errorf("initial fetch of jwks from provider: %w", err))
	}

	return cache, jwks
}
