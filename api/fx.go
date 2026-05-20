package api

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/keys"
)

type resultParams struct {
	fx.In

	Readiness    *Readiness
	Keys         JWKSSource
	OIDCIssuer   string `name:"oidc_issuer"`
	OIDCBasePath string `name:"oidc_base_path"`

	// Registrars are contributed by feature packages (e.g. oidc) into the
	// shared group so they can append Huma operations without api importing
	// them. They land on the OIDC-surface adapter, which moves under
	// basePath when one is configured.
	Registrars []func(huma.API) `group:"api_registrars"`

	// RootRegistrars also avoid api importing the feature package, but they
	// pin the registered routes to the listener root regardless of
	// basePath. admin/ uses this so /admin/keys is never shadowed by a
	// /idp-style OIDC prefix.
	RootRegistrars []func(huma.API) `group:"root_registrars"`
}

func newResult(p resultParams) *Result {
	opts := []Option{
		WithBasePath(p.OIDCBasePath),
		WithWellKnown(p.Keys, p.OIDCIssuer),
	}
	for _, r := range p.Registrars {
		opts = append(opts, WithRegistrar(r))
	}
	for _, r := range p.RootRegistrars {
		opts = append(opts, WithRootRegistrar(r))
	}
	return New(p.Readiness, opts...)
}

// keysAsJWKSSource adapts the concrete *keys.Keys (provided by keys.Fx) to
// api's narrow JWKSSource. The binding lives here, in the consumer, rather
// than via fx.As in keys.Fx: keys is the lower-level domain package and must
// not import api. *keys.Keys satisfies JWKSSource structurally; this is just
// the typed hand-off.
func keysAsJWKSSource(k *keys.Keys) JWKSSource { return k }

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(NewReadiness),
		fx.Provide(keysAsJWKSSource),
		fx.Provide(newResult),
	)
}
