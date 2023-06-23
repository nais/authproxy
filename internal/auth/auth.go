package auth

import (
	"net/http"
	"strings"
)

type Handler func(h http.Handler) http.Handler

type Provider interface {
	Handler() (Handler, error)
}

var _ Provider = &PSK{}

type PSK struct {
	authHeader string
	apiKey     string
}

func PreSharedKey(authHeader, apiKey string) *PSK {
	return &PSK{
		authHeader: authHeader,
		apiKey:     apiKey,
	}
}

func (p *PSK) Handler() (Handler, error) {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get(p.authHeader)

			token := strings.ReplaceAll(header, "Bearer ", "")
			token = strings.TrimSpace(token)
			if token != strings.TrimSpace(p.apiKey) {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			handler.ServeHTTP(w, r)
		})
	}, nil
}

var _ Provider = &NoAuth{}

type NoAuth struct{}

func NoOp() *NoAuth {
	return &NoAuth{}
}

func (n NoAuth) Handler() (Handler, error) {
	return func(h http.Handler) http.Handler {
		return h
	}, nil
}
