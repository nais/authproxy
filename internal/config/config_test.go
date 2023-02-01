package config

import (
	"testing"

	"authproxy/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestConfigPreSharedKey(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *Config
		assertFunc func(provider auth.Provider, err error)
	}{
		{
			name: "valid pre-shared key config",
			cfg: &Config{
				AuthProvider:     "key",
				AuthPreSharedKey: "1234",
				AuthTokenHeader:  "Authorization",
			},
			assertFunc: func(provider auth.Provider, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			},
		},
		{
			name: "missing auth-pre-shared-key",
			cfg: &Config{
				AuthProvider:    "key",
				AuthTokenHeader: "Authorization",
			},
			assertFunc: func(_ auth.Provider, err error) {
				assert.Error(t, err)
				assert.Containsf(t, err.Error(), "auth-pre-shared-key", "expected error to contain '%s' but got '%s'", "auth-pre-shared-key", err.Error())
			},
		},
		{
			name: "missing auth-token-header",
			cfg: &Config{
				AuthProvider:     "key",
				AuthPreSharedKey: "1234",
			},
			assertFunc: func(_ auth.Provider, err error) {
				assert.Error(t, err)
				assert.Containsf(t, err.Error(), "auth-token-header", "expected error to contain '%s' but got '%s'", "auth-token-header", err.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.cfg.Auth()
			tt.assertFunc(p, err)
		})
	}
}

func TestConfigIAP(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *Config
		assertFunc func(provider auth.Provider, err error)
	}{
		{
			name: "valid JWT config",
			cfg: &Config{
				AuthProvider: "iap",
				AuthAudience: "test",
			},
			assertFunc: func(provider auth.Provider, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			},
		},
		{
			name: "missing auth-audience",
			cfg: &Config{
				AuthProvider: "iap",
			},
			assertFunc: func(_ auth.Provider, err error) {
				assert.Error(t, err)
				assert.Containsf(t, err.Error(), "auth-audience", "expected error to contain '%s' but got '%s'", "auth-jwks-url", err.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.cfg.Auth()
			tt.assertFunc(p, err)
		})
	}
}

func TestConfigJWT(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *Config
		assertFunc func(provider auth.Provider, err error)
	}{
		{
			name: "valid JWT config",
			cfg: &Config{
				AuthProvider:       "jwt",
				AuthJwksUrl:        "http://localhost",
				AuthRequiredClaims: "iss=http://localhost:1234, aud=yolo",
			},
			assertFunc: func(provider auth.Provider, err error) {
				assert.NoError(t, err)
				assert.IsTypef(t, &auth.JWTAuth{}, provider, "expected provider to be of type '%T' but got '%T'", &auth.JWTAuth{}, provider)
			},
		},
		{
			name: "missing auth-jwks-url",
			cfg: &Config{
				AuthProvider: "jwt",
			},
			assertFunc: func(_ auth.Provider, err error) {
				assert.Error(t, err)
				assert.Containsf(t, err.Error(), "auth-jwks-url", "expected error to contain '%s' but got '%s'", "auth-jwks-url", err.Error())
			},
		},
		{
			name: "missing auth-required-claims",
			cfg: &Config{
				AuthProvider: "jwt",
				AuthJwksUrl:  "http://localhost:1234",
			},
			assertFunc: func(_ auth.Provider, err error) {
				assert.Error(t, err)
				assert.Containsf(t, err.Error(), "auth-required-claims", "expected error to contain '%s' but got '%s'", "auth-required-claims", err.Error())
			},
		},
		{
			name: "auth-required-claims has invalid format",
			cfg: &Config{
				AuthProvider:       "jwt",
				AuthJwksUrl:        "http://localhost:1234",
				AuthRequiredClaims: "iss: http://localhost:1234",
			},
			assertFunc: func(_ auth.Provider, err error) {
				assert.Error(t, err)
				assert.Containsf(t, err.Error(), "auth-required-claims", "expected error to contain '%s' but got '%s'", "auth-required-claims", err.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.cfg.Auth()
			tt.assertFunc(p, err)
		})
	}
}

func TestToClaimMap(t *testing.T) {
	_, err := toClaimMap("key")
	assert.Error(t, err)
	m, err := toClaimMap("key1 = value1, key2 = value2")
	assert.NoError(t, err)
	assert.Equal(t, map[string]any{"key1": "value1", "key2": "value2"}, m)
}
