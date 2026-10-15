package proxy

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strings"
)

type ReverseProxy struct {
	*httputil.ReverseProxy
}

func New(scheme, upstreamHost string) *ReverseProxy {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Host = upstreamHost
			pr.Out.URL.Scheme = strings.ToLower(scheme)
			pr.Out.Host = upstreamHost
			preserveForwardedHeaders(pr)

			// TODO: get token from context and pass through if we need this functionality
			//accessToken, ok := mv.AccessTokenFrom(r.Context())
			/*if ok {
				r.Header.Set("authorization", "Bearer "+accessToken)
			}*/
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

// Rewrite strips forwarding headers from the outbound request; restore them and
// append the client IP to X-Forwarded-For, matching the previous Director behavior.
// Headers the client marked as hop-by-hop via Connection are not restored.
func preserveForwardedHeaders(pr *httputil.ProxyRequest) {
	hopByHop := map[string]bool{}
	for _, v := range pr.In.Header.Values("Connection") {
		for f := range strings.SplitSeq(v, ",") {
			hopByHop[textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(f))] = true
		}
	}

	for _, h := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if v, ok := pr.In.Header[h]; ok && !hopByHop[h] {
			pr.Out.Header[h] = v
		}
	}

	clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr)
	if err != nil {
		return
	}
	if prior := pr.In.Header.Values("X-Forwarded-For"); len(prior) > 0 && !hopByHop["X-Forwarded-For"] {
		clientIP = strings.Join(prior, ", ") + ", " + clientIP
	}
	pr.Out.Header.Set("X-Forwarded-For", clientIP)
}

func (rp *ReverseProxy) Handle() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(w, r)
	}
}
