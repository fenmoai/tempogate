package api

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/keys"
)

type resultParams struct {
	fx.In

	Readiness  *Readiness
	Keys       *keys.Keys
	OIDCIssuer string `name:"oidc_issuer"`

	// Registrars are contributed by feature packages (e.g. oidc) into the
	// shared group so they can append Huma operations without api importing
	// them.
	Registrars []func(huma.API) `group:"api_registrars"`
}

func newResult(p resultParams) *Result {
	opts := []Option{WithWellKnown(p.Keys, p.OIDCIssuer)}
	for _, r := range p.Registrars {
		opts = append(opts, WithRegistrar(r))
	}
	return New(p.Readiness, opts...)
}

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(NewReadiness),
		fx.Provide(newResult),
	)
}
