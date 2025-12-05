package proxy

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"authproxy/internal/auth"
)

type ReverseProxy struct {
	*httputil.ReverseProxy
}

func New(scheme, upstreamHost string) *ReverseProxy {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Instruct http.ReverseProxy to not modify X-Forwarded-For header
			// r.Header["X-Forwarded-For"] = nil
			// Request should go to correct host
			r.URL.Host = upstreamHost
			r.URL.Scheme = strings.ToLower(scheme)
			r.Host = upstreamHost

			accessToken, ok := r.Context().Value(auth.CtxAccessToken).(string)
			if ok {
				r.Header.Set("authorization", "Bearer "+accessToken)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger := LogEntryFrom(r)

			if errors.Is(err, context.Canceled) {
				w.WriteHeader(499)
			} else {
				logger.Warnf("reverseproxy: proxy error: %+v", err)
				w.WriteHeader(http.StatusBadGateway)
			}
		},
		ErrorLog: log.New(logrusErrorWriter{}, "reverseproxy: ", 0),
	}
	return &ReverseProxy{rp}
}

func (rp *ReverseProxy) Handle() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(w, r)
	}
}
