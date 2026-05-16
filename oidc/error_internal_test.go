package oidc

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOAuthErrorImplementsStatusError(t *testing.T) {
	e := oauthErr(http.StatusBadRequest, "invalid_client", "unknown client_id")
	assert.Equal(t, http.StatusBadRequest, e.GetStatus())
	assert.Equal(t, "invalid_client: unknown client_id", e.Error())
}
