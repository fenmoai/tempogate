package log

import "go.uber.org/fx"

func Fx() fx.Option {
	return fx.Provide(New)
}
