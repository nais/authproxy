package config

import (
	"errors"
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
	AuthIssuer         string `json:"auth-issuer"`
	AuthTokenHeader    string `json:"auth-token-header"`
	AuthPreSharedKey   string `json:"auth-pre-shared-key"`
}

func DefaultConfig() *Config {
	return &Config{
		BindAddress:        ":8080",
		MetricsBindAddress: ":8081",
		LogLevel:           "info",
		UpstreamScheme:     "https",
	}
}

func (c *Config) Auth() (auth.Provider, error) {
	p := strings.ToLower(c.AuthProvider)

	switch p {
	case "iap":
		if c.AuthAudience == "" {
			return nil, errors.New("auth-audience must be set")
		}
		return auth.IAP(c.AuthAudience), nil
	case "key":
		if c.AuthPreSharedKey == "" {
			return nil, errors.New("auth-pre-shared-key must be set")
		}
		return auth.PreSharedKey(c.AuthTokenHeader, c.AuthPreSharedKey), nil
	case "no-op":
		return auth.NoOp(), nil
	default:
		return nil, errors.New("unknown auth-provider:" + p)
	}
}
