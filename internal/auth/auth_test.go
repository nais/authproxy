package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreSharedKeyAuthorized(t *testing.T) {
	provider, err := testProvider(PreSharedKey("Authorization", "FooBar123_%"))

	// correct header name and value
	assert.NoError(t, err)
	r1, err := provider.withRequest("Authorization", "FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, r1.Code)

	// correct header name and value, allow prefix with "Bearer "
	r2, err := provider.withRequest("Authorization", "Bearer FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, r2.Code)
}

func TestPreSharedKeyUnauthorized(t *testing.T) {
	provider, err := testProvider(PreSharedKey("Authorization", "FooBar123_%"))

	// wrong header name
	assert.NoError(t, err)
	r1, err := provider.withRequest("Not-Authorization", "FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, r1.Code)

	// mismatched header value
	r2, err := provider.withRequest("Authorization", "Not-FooBar123_%")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, r2.Code)
}
