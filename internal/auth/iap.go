package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/api/idtoken"
)

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

			payload, err := p.validator.Validate(r.Context(), jwt, p.aud)
			if err != nil {
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
