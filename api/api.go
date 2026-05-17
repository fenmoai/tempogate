// Package api is the public HTTP surface: /healthz, /readyz, and (via feature
// registrars) the OIDC/JWKS endpoints.
//
// By default everything is served at the root. With WithBasePath set (the path
// component of OIDC__ISSUER), the OIDC surface is mounted under that prefix so
// tempogate can be co-hosted on a shared hostname; /healthz and /readyz stay
// at the root regardless — they are k8s-probe-only and never path-routed.
package api

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/fenmoai/tempogate/buildinfo"
)

type apiConfig struct {
	registrars []func(huma.API)
	basePath   string
}

type Option func(*apiConfig)

// WithRegistrar lets feature modules (OIDC, admin, JWKS) plug additional Huma
// route registrations onto the OIDC-surface adapter.
func WithRegistrar(fn func(huma.API)) Option {
	return func(c *apiConfig) { c.registrars = append(c.registrars, fn) }
}

// WithBasePath mounts the OIDC surface under a URL path prefix — the path
// component of OIDC__ISSUER (e.g. "/idp"). Health probes stay at the root.
// Empty ⇒ root, the historical default (zero behavioural change).
func WithBasePath(p string) Option {
	return func(c *apiConfig) { c.basePath = p }
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

	// Root mode: one adapter, health + OIDC at the root. Byte-identical to
	// the original behaviour for every deployment that doesn't set a path.
	if cfg.basePath == "" {
		a := humago.NewWithPrefix(mux, "", huma.DefaultConfig("tempogate", buildinfo.Version()))
		registerHealth(a, readiness)
		for _, fn := range cfg.registrars {
			fn(a)
		}
		return &Result{API: a, Handler: mux, Prefix: ""}
	}

	// Base-path mode: two adapters on one mux. Health stays at the root
	// (probe-only); the OIDC surface mounts natively under basePath so the
	// served routes, the discovery document, and the iss claim stay in
	// lockstep with no proxy StripPrefix. The health adapter serves no
	// OpenAPI/docs so the root surface is exactly /healthz + /readyz.
	healthCfg := huma.DefaultConfig("tempogate", buildinfo.Version())
	healthCfg.OpenAPIPath = ""
	healthCfg.DocsPath = ""
	healthCfg.SchemasPath = ""
	healthAPI := humago.NewWithPrefix(mux, "", healthCfg)
	registerHealth(healthAPI, readiness)

	oidcAPI := humago.NewWithPrefix(mux, cfg.basePath, huma.DefaultConfig("tempogate", buildinfo.Version()))
	for _, fn := range cfg.registrars {
		fn(oidcAPI)
	}

	return &Result{API: oidcAPI, Handler: mux, Prefix: cfg.basePath}
}
