package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"authproxy/internal/config"

	"github.com/stretchr/testify/assert"
)

func TestRouter(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AuthProvider = "key"
	cfg.AuthPreSharedKey = "test"
	cfg.AuthTokenHeader = "Authorization"
	cfg.UpstreamScheme = "http"
	cfg.LogLevel = "debug"

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer proxyServer.Close()

	u, err := url.Parse(proxyServer.URL)
	assert.NoError(t, err)
	cfg.UpstreamHost = u.Host

	r := Router(cfg)
	s := httptest.NewServer(r)
	defer s.Close()

	tests := []struct {
		name       string
		headers    []string
		statusCode int
	}{
		{
			name:       "invoke router without auth header",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "invoke router with valid auth header",
			statusCode: http.StatusOK,
			headers: []string{
				"Authorization", "Bearer test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := req(s.URL, tt.headers...)
			assert.NoError(t, err)
			got, err := s.Client().Do(r)
			assert.NoError(t, err)
			assert.Equal(t, tt.statusCode, got.StatusCode)
		})
	}
}

func req(url string, header ...string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return req, nil
}
