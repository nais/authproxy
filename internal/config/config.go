package config

import (
	"errors"
	"fmt"
	"strings"

	"authproxy/internal/auth"
)

type Config struct {
	BindAddress        string `json:"bind-address"`
	MetricsBindAddress string `json:"metrics-bind-address"`
	LogLevel           string `json:"log-level"`
	UpstreamHost       string `json:"upstream-host"`
	UpstreamScheme     string `json:"upstream-scheme"`
	AuthProvider       string `json:"auth-provider"`
	AuthAudience       string `json:"auth-audience"`
	AuthJwksUrl        string `json:"auth-jwks-url"`
	AuthRequiredClaims string `json:"auth-required-claims"`
	AuthTokenHeader    string `json:"auth-token-header"`
	AuthPreSharedKey   string `json:"auth-pre-shared-key"`
}

func DefaultConfig() *Config {
	return &Config{
		BindAddress:        "127.0.0.1:8080",
		MetricsBindAddress: "127.0.0.1:8081",
		LogLevel:           "info",
		UpstreamScheme:     "https",
	}
}

func (c *Config) Auth() (auth.Provider, error) {
	var p auth.Provider
	var err error

	switch strings.ToLower(c.AuthProvider) {
	case "iap":
		if c.AuthAudience == "" {
			return nil, errors.New("auth-audience must be set")
		}
		p = auth.IAP(c.AuthAudience)
	case "jwt":
		if c.AuthJwksUrl == "" {
			return nil, errors.New("auth-jwks-url must be set")
		}
		if c.AuthTokenHeader == "" {
			c.AuthTokenHeader = "Authorization"
		}
		if c.AuthRequiredClaims == "" {
			return nil, errors.New("auth-required-claims must be set")
		}
		claims, err := toClaimMap(c.AuthRequiredClaims)
		if err != nil {
			return nil, fmt.Errorf("auth-required-claims invalid format: %w", err)
		}
		p, err = auth.JWT(c.AuthTokenHeader, c.AuthJwksUrl, claims)
		if err != nil {
			return nil, fmt.Errorf("creating JWT auth provider: %w", err)
		}
	case "key":
		if c.AuthPreSharedKey == "" {
			return nil, errors.New("auth-pre-shared-key must be set")
		}
		if c.AuthTokenHeader == "" {
			return nil, errors.New("auth-token-header must be set")
		}
		p = auth.PreSharedKey(c.AuthTokenHeader, c.AuthPreSharedKey)
	case "no-op":
		p = auth.NoOp()
	default:
		return nil, errors.New("unknown auth-provider:" + strings.ToLower(c.AuthProvider))
	}

	if err != nil {
		return nil, err
	}
	return p, nil
}

func toClaimMap(s string) (map[string]any, error) {
	m := make(map[string]any)

	pairs := strings.Split(s, ",")
	if len(pairs) == 0 {
		return nil, errors.New("must be a comma separated list: " + s)
	}
	for _, kv := range pairs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New("should be key/value separated with '='" + kv)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		m[key] = value
	}

	return m, nil
}
