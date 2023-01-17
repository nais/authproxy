package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreSharedKey(t *testing.T) {

	provider := PreSharedKey("Authorization", "AbC123%")

	reqWithBearer, err := req("Authorization", "Bearer AbC123%")
	assert.NoError(t, err)

	rr := recordAndServe(reqWithBearer, provider(handler()))

	assert.Equal(t, http.StatusOK, rr.Code)

	reqWithoutBearer, err := req("Authorization", "AbC123%")
	assert.NoError(t, err)

	rr = recordAndServe(reqWithoutBearer, provider(handler()))

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestPreSharedKeyUnauthorized(t *testing.T) {

	provider := PreSharedKey("Authorization", "Bearer 123")

	reqWrongHeader, err := req("Not-Authorization", "Bearer 123")
	assert.NoError(t, err)

	rr := recordAndServe(reqWrongHeader, provider(handler()))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	reqInvalidHeaderValue, err := req("Authorization", "Bearer invalid")
	assert.NoError(t, err)

	rr = recordAndServe(reqInvalidHeaderValue, provider(handler()))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func recordAndServe(req *http.Request, handler http.Handler) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func req(header ...string) (*http.Request, error) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return nil, err
	}
	if len(header) > 0 {
		req.Header.Set(header[0], header[1])
	}
	return req, nil
}
