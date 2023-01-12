package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/api/idtoken"
)

type Provider func(h http.Handler) http.Handler

func NoOp() Provider {
	return func(h http.Handler) http.Handler {
		return h
	}
}

func IAP(aud string) Provider {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwt := r.Header.Get("X-Goog-IAP-JWT-Assertion")

			if jwt == "" {
				log.Debugf("no JWT token found in request")
				http.Error(w, fmt.Sprintf("missing token from header %s", "X-Goog-IAP-JWT-Assertion"), http.StatusUnauthorized)
				return
			}

			payload, err := idtoken.Validate(r.Context(), jwt, aud)
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
	}
}

func PreSharedKey(authHeader, apiKey string) Provider {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get(authHeader)
			h := strings.TrimSpace(strings.ToLower(r.Header.Get(authHeader)))

			token := strings.ReplaceAll(h, "bearer ", "")
			if token != strings.TrimSpace(apiKey) {
				log.Debugf("header '%s' has invalid key '%s'", authHeader, header)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			handler.ServeHTTP(w, r)
		})
	}
}
