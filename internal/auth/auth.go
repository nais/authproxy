package auth

import (
	"net/http"
	"time"

	"google.golang.org/api/idtoken"
)

type Provider func(h http.Handler) http.Handler

func VerifyIAP(aud string) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwt := r.Header.Get("X-Goog-IAP-JWT-Assertion")

			payload, err := idtoken.Validate(r.Context(), jwt, aud)
			if err != nil {
				http.Error(w, "Invalid JWT token", http.StatusUnauthorized)
				return
			}

			if time.Unix(payload.IssuedAt, 0).After(time.Now().Add(30 * time.Second)) {
				http.Error(w, "JWT token is in the future", http.StatusUnauthorized)
				return
			}

			if payload.Issuer != "https://cloud.google.com/iap" {
				http.Error(w, "Invalid JWT token issuer", http.StatusUnauthorized)
				return
			}

			h.ServeHTTP(w, r)
		})
	}
}
