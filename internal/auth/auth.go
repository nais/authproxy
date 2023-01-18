package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/api/idtoken"
)

type Handler func(h http.Handler) http.Handler

type Provider interface {
	Handler() (Handler, error)
}

var _ Provider = &GoogleIAP{}

type GoogleIAP struct {
	aud       string
	validator *idtoken.Validator
}

func IAP(aud string) *GoogleIAP {
	return &GoogleIAP{
		aud: aud,
	}
}

func (p *GoogleIAP) Handler() (Handler, error) {
	if p.validator == nil {
		v, err := idtoken.NewValidator(context.Background())
		if err != nil {
			return nil, err
		}
		p.validator = v
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwt := r.Header.Get("X-Goog-IAP-JWT-Assertion")

			if jwt == "" {
				log.Debugf("no JWT token found in request")
				http.Error(w, fmt.Sprintf("missing token from header %s", "X-Goog-IAP-JWT-Assertion"), http.StatusUnauthorized)
				return
			}

			payload, err := p.validator.Validate(r.Context(), jwt, p.aud) //idtoken.Validate(r.Context(), jwt, aud)
			if err != nil {
				fmt.Printf("%v\n", err)
				log.Debugf("invalid JWT token: %v", err)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			if time.Unix(payload.IssuedAt, 0).After(time.Now().Add(30 * time.Second)) {
				log.Debugf("JWT token is in the future")
				http.Error(w, "JWT token is in the future", http.StatusUnauthorized)
				return
			}

			if payload.Issuer != "https://cloud.google.com/iap" {
				log.Debugf("invalid JWT token issuer")
				http.Error(w, "Invalid JWT token issuer", http.StatusUnauthorized)
				return
			}

			h.ServeHTTP(w, r)
		})
	}, nil
}

func (p *GoogleIAP) WithValidator(v *idtoken.Validator) *GoogleIAP {
	p.validator = v
	return p
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
				log.Debugf("header '%s' has invalid key '%s'", p.authHeader, header)
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
