package api

import (
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/keys"
)

type resultParams struct {
	fx.In

	Readiness  *Readiness
	Keys       *keys.Keys
	OIDCIssuer string `name:"oidc_issuer"`
}

func newResult(p resultParams) *Result {
	return New(p.Readiness, WithWellKnown(p.Keys, p.OIDCIssuer))
}

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(NewReadiness),
		fx.Provide(newResult),
	)
}
