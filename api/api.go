// Package api is the public HTTP surface. Today it serves only /healthz and
// /readyz under no prefix; OIDC, JWKS, and admin endpoints land in later
// epics by appending huma operations to the same Result.API.
package api

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/fenmoai/tempogate/buildinfo"
)

const apiPrefix = ""

type apiConfig struct {
	registrars []func(huma.API)
}

type Option func(*apiConfig)

// WithRegistrar lets future epics (OIDC, admin, JWKS) plug additional Huma
// route registrations into the same humago adapter.
func WithRegistrar(fn func(huma.API)) Option {
	return func(c *apiConfig) { c.registrars = append(c.registrars, fn) }
}

type Result struct {
	API     huma.API
	Handler http.Handler
	Prefix  string
}

func New(readiness *Readiness, opts ...Option) *Result {
	cfg := &apiConfig{}
	for _, o := range opts {
		o(cfg)
	}

	mux := http.NewServeMux()
	api := humago.NewWithPrefix(mux, apiPrefix, huma.DefaultConfig("tempogate", buildinfo.Version()))

	registerHealth(api, readiness)
	for _, fn := range cfg.registrars {
		fn(api)
	}

	return &Result{
		API:     api,
		Handler: mux,
		Prefix:  apiPrefix,
	}
}
