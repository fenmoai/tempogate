package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
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
// equal the URL relying parties fetch it from). Extra Options let individual
// tests add registrars (e.g. a root-only fixture for admin-style endpoints).
func serveAt(t *testing.T, basePath string, extra ...api.Option) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + srv.Listener.Addr().String() + basePath
	opts := []api.Option{
		api.WithBasePath(basePath),
		api.WithWellKnown(newKeys(t), issuer),
	}
	opts = append(opts, extra...)
	res := api.New(api.NewReadiness(), opts...)
	srv.Config.Handler = res.Handler
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, issuer
}

// adminProbe is a test-only Huma registrar standing in for the real admin
// registrar: it registers a single `GET /admin/probe` so the basepath suite
// can assert mount location without depending on the admin package (an
// import would cycle: admin → state/sqlite → … and api wires admin's
// registrars in production via the same Option machinery exercised here).
func adminProbe(a huma.API) {
	type out struct {
		Body struct {
			OK bool `json:"ok"`
		}
	}
	huma.Register(a, huma.Operation{
		OperationID: "admin-probe",
		Method:      http.MethodGet,
		Path:        "/admin/probe",
		Summary:     "probe",
		Tags:        []string{"admin"},
	}, func(_ context.Context, _ *struct{}) (*out, error) {
		o := &out{}
		o.Body.OK = true
		return o, nil
	})
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

// TestRootRegistrarStaysAtRootUnderBasePath locks the admin contract:
// routes registered via WithRootRegistrar are always served at the root,
// regardless of OIDC base path. In base-path mode this means /admin/probe
// answers and /idp/admin/probe must 404 — the OIDC prefix MUST NOT shadow
// the admin surface, which a future commit will move to a private listener
// where any path overlap with OIDC would be a deployment hazard.
func TestRootRegistrarStaysAtRootUnderBasePath(t *testing.T) {
	t.Parallel()
	srv, _ := serveAt(t, "/idp", api.WithRootRegistrar(adminProbe))

	code, _ := get(t, srv.URL+"/admin/probe")
	assert.Equal(t, http.StatusOK, code, "/admin/* must answer at root in base-path mode")

	prefixed, _ := get(t, srv.URL+"/idp/admin/probe")
	assert.Equal(t, http.StatusNotFound, prefixed,
		"/admin/* must NOT be reachable under the OIDC base path")

	// And the OIDC surface is unaffected by adding a root registrar.
	hc, _ := get(t, srv.URL+"/idp/.well-known/openid-configuration")
	assert.Equal(t, http.StatusOK, hc, "OIDC surface still serves under its prefix")
}

// TestRootRegistrarServesAtRootInRootMode: with no base path everything is
// already at root; the WithRootRegistrar option must still work and not
// double-register.
func TestRootRegistrarServesAtRootInRootMode(t *testing.T) {
	t.Parallel()
	srv, _ := serveAt(t, "", api.WithRootRegistrar(adminProbe))

	code, _ := get(t, srv.URL+"/admin/probe")
	assert.Equal(t, http.StatusOK, code)

	// Health and OIDC keep working — root registrar is additive.
	hc, _ := get(t, srv.URL+"/healthz")
	assert.Equal(t, http.StatusOK, hc)
	oc, _ := get(t, srv.URL+"/.well-known/openid-configuration")
	assert.Equal(t, http.StatusOK, oc)
}
