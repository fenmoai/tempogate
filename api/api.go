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
	// registrars are mounted on the OIDC-surface adapter, which moves under
	// basePath when one is set. JWKS + discovery use this so the
	// well-known URLs match the issuer in the discovery document.
	registrars []func(huma.API)
	// rootRegistrars are always mounted at the root of the public listener
	// regardless of basePath. The admin surface uses this so /admin/keys
	// stays at root even when OIDC is path-prefixed under /idp; a future
	// commit moves admin to its own private listener and any overlap with
	// the OIDC prefix would be a deployment hazard.
	rootRegistrars []func(huma.API)
	basePath       string
}

type Option func(*apiConfig)

// WithRegistrar lets feature modules (OIDC, JWKS) plug additional Huma route
// registrations onto the OIDC-surface adapter — that surface moves under
// basePath when one is set.
func WithRegistrar(fn func(huma.API)) Option {
	return func(c *apiConfig) { c.registrars = append(c.registrars, fn) }
}

// WithRootRegistrar mounts a Huma registrar at the root regardless of
// basePath. Use for surfaces that must never be shadowed by the OIDC
// prefix — currently /admin/keys, which a follow-up will move off the
// public listener entirely.
func WithRootRegistrar(fn func(huma.API)) Option {
	return func(c *apiConfig) { c.rootRegistrars = append(c.rootRegistrars, fn) }
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

	// Root mode: one adapter, every registrar at the root.
	// Byte-identical to the original behaviour for every deployment that
	// doesn't set a path — root registrars and OIDC registrars all land on
	// the same adapter, since "root" and "basePath" are the same place.
	if cfg.basePath == "" {
		a := humago.NewWithPrefix(mux, "", huma.DefaultConfig("tempogate", buildinfo.Version()))
		registerHealth(a, readiness)
		for _, fn := range cfg.rootRegistrars {
			fn(a)
		}
		for _, fn := range cfg.registrars {
			fn(a)
		}
		return &Result{API: a, Handler: mux, Prefix: ""}
	}

	// Base-path mode: up to three adapters on one mux.
	//   - healthAPI: root, probe-only (no OpenAPI/docs). Today serves
	//     /healthz and /readyz; intentionally minimal so the root surface
	//     stays an obvious "k8s probes only" target.
	//   - rootAPI: root, full OpenAPI/docs — created only when at least one
	//     root registrar is present, so callers without admin-style routes
	//     pay no extra surface. Its OpenAPI spec describes the root-mounted
	//     routes (e.g. /admin/keys); the OIDC spec stays under basePath.
	//   - oidcAPI: basePath, full OpenAPI/docs. The OIDC surface mounts
	//     natively under basePath so served routes, the discovery document,
	//     and the iss claim stay in lockstep with no proxy StripPrefix.
	healthCfg := huma.DefaultConfig("tempogate", buildinfo.Version())
	healthCfg.OpenAPIPath = ""
	healthCfg.DocsPath = ""
	healthCfg.SchemasPath = ""
	healthAPI := humago.NewWithPrefix(mux, "", healthCfg)
	registerHealth(healthAPI, readiness)

	if len(cfg.rootRegistrars) > 0 {
		rootAPI := humago.NewWithPrefix(mux, "", huma.DefaultConfig("tempogate-root", buildinfo.Version()))
		for _, fn := range cfg.rootRegistrars {
			fn(rootAPI)
		}
	}

	oidcAPI := humago.NewWithPrefix(mux, cfg.basePath, huma.DefaultConfig("tempogate", buildinfo.Version()))
	for _, fn := range cfg.registrars {
		fn(oidcAPI)
	}

	return &Result{API: oidcAPI, Handler: mux, Prefix: cfg.basePath}
}
