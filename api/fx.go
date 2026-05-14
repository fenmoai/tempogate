package api

import "go.uber.org/fx"

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(NewReadiness),
		fx.Provide(func(r *Readiness) *Result { return New(r) }),
	)
}
