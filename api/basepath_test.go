package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fenmoai/tempogate/api"
	"github.com/fenmoai/tempogate/keys"
)

// newKeys builds a keypair-backed JWKS source for WithWellKnown, reusing the
// in-memory store stub from wellknown_test.go (same api_test package).
func newKeys(t *testing.T) *keys.Keys {
	t.Helper()
	k := keys.New(keys.WithStore(&memKeyStore{}), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	require.NoError(t, k.Init(context.Background()))
	return k
}

// serveAt binds an httptest server, then constructs the API with an issuer that
// embeds basePath, mirroring real deployment (the discovery doc's issuer must
// equal the URL relying parties fetch it from).
func serveAt(t *testing.T, basePath string) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + srv.Listener.Addr().String() + basePath
	res := api.New(api.NewReadiness(),
		api.WithBasePath(basePath),
		api.WithWellKnown(newKeys(t), issuer),
	)
	srv.Config.Handler = res.Handler
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, issuer
}

// TestBasePathMode: with a non-empty base path the OIDC surface is served
// under it, the discovery doc advertises issuer-relative (prefixed) endpoints,
// and /healthz / /readyz stay at root (k8s-probe-only, never path-routed).
func TestBasePathMode(t *testing.T) {
	t.Parallel()
	srv, issuer := serveAt(t, "/idp")

	code, body := get(t, srv.URL+"/idp/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, code)
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	assert.Equal(t, issuer, doc.Issuer)
	assert.Equal(t, issuer+"/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, issuer+"/token", doc.TokenEndpoint)
	assert.Equal(t, issuer+"/.well-known/jwks.json", doc.JwksURI)

	jc, _ := get(t, srv.URL+"/idp/.well-known/jwks.json")
	assert.Equal(t, http.StatusOK, jc, "JWKS served under the prefix")

	// Health stays at root regardless of the prefix.
	hc, _ := get(t, srv.URL+"/healthz")
	assert.Equal(t, http.StatusOK, hc, "/healthz must stay at root")

	// The OIDC surface must NOT answer at root, and health must NOT move
	// under the prefix.
	rc, _ := get(t, srv.URL+"/.well-known/openid-configuration")
	assert.Equal(t, http.StatusNotFound, rc, "discovery must not be at root in base-path mode")
	ph, _ := get(t, srv.URL+"/idp/healthz")
	assert.Equal(t, http.StatusNotFound, ph, "/healthz must not move under the prefix")
}

// TestRootModeUnchanged: an empty base path is byte-identical to today —
// OIDC + health both at root (regression guard for existing deployments).
func TestRootModeUnchanged(t *testing.T) {
	t.Parallel()
	srv, issuer := serveAt(t, "")

	code, body := get(t, srv.URL+"/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, code)
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	assert.Equal(t, issuer, doc.Issuer)
	assert.Equal(t, issuer+"/authorize", doc.AuthorizationEndpoint)

	hc, _ := get(t, srv.URL+"/healthz")
	assert.Equal(t, http.StatusOK, hc)
}
