package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

type TestProvider struct {
	Handler
}

func TestIAPAuthorized(t *testing.T) {
	jwks, err := newJwkSet("1234")
	assert.NoError(t, err)

	validator, err := idtoken.NewValidator(context.Background(), option.WithHTTPClient(httpClient(jwks)))
	assert.NoError(t, err)
	provider, err := testProvider(IAP("google_iap_audience").WithValidator(validator))
	assert.NoError(t, err)

	t1, err := defaultIapToken("google_iap_audience").sign(jwks)
	r1, err := provider.withRequest("X-Goog-IAP-JWT-Assertion", t1)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, r1.Code)
}

func TestIAPUnauthorized(t *testing.T) {

	validAudience := "google_iap_audience"
	jwks, err := newJwkSet("1234")
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

				token, err := defaultIapToken(validAudience).sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "token expired",
			tokenFunc: func(t *testing.T) string {
				iat := time.Now().Add(-20 * time.Second)
				token, err := iapToken(iat, 19*time.Second, validAudience).sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "token is in the future",
			tokenFunc: func(t *testing.T) string {
				iat := time.Now().Add(40 * time.Second)
				token, err := iapToken(iat, 1*time.Minute, validAudience).sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "invalid audience",
			tokenFunc: func(t *testing.T) string {
				token, err := defaultIapToken("invalid_audience").sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
		{
			name: "invalid issuer",
			tokenFunc: func(t *testing.T) string {
				token, err := defaultIapToken(validAudience).with("iss", "invalid").sign(jwks)
				assert.NoError(t, err)
				return token
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := idtoken.NewValidator(context.Background(), option.WithHTTPClient(httpClient(jwks)))
			assert.NoError(t, err)
			provider, err := testProvider(IAP(validAudience).WithValidator(validator))
			assert.NoError(t, err)

			t1 := tt.tokenFunc(t)
			header := tt.headerName
			if header == "" {
				header = "X-Goog-IAP-JWT-Assertion"
			}
			r1, err := provider.withRequest(header, t1)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, r1.Code)
			println(r1.Body.String())
		})
	}
}

func TestPreSharedKeyAuthorized(t *testing.T) {
	provider, err := testProvider(PreSharedKey("Authorization", "FooBar123_%"))

	// correct header name and value
	assert.NoError(t, err)
	r1, err := provider.withRequest("Authorization", "FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, r1.Code)

	// correct header name and value, allow prefix with "Bearer "
	r2, err := provider.withRequest("Authorization", "Bearer FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, r2.Code)
}

func TestPreSharedKeyUnauthorized(t *testing.T) {
	provider, err := testProvider(PreSharedKey("Authorization", "FooBar123_%"))

	// wrong header name
	assert.NoError(t, err)
	r1, err := provider.withRequest("Not-Authorization", "FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, r1.Code)

	// mismatched header value
	r2, err := provider.withRequest("Authorization", "Not-FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, r2.Code)
}
