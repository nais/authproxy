package config

import (
	"errors"
	"strings"

	"authproxy/internal/auth"
)

type Config struct {
	BindAddress  string `json:"bind-address"`
	LogLevel     string `json:"log-level"`
	UpstreamHost string `json:"upstream-host"`
	AuthProvider string `json:"auth-provider"`
	AuthAudience string `json:"auth-audience"`
	AuthIssuer   string `json:"auth-issuer"`
}

func DefaultConfig() *Config {
	return &Config{
		BindAddress: ":8080",
		LogLevel:    "info",
	}
}

func (c *Config) Auth() (auth.Provider, error) {
	p := strings.ToLower(c.AuthProvider)

	switch p {
	case "iap":
		return auth.VerifyIAP(c.AuthAudience), nil
	default:
		return nil, errors.New("unknown auth provider")
	}
}
