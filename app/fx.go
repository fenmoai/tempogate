// Package app is the fx composition root for the tempogate binary.
//
// Subsequent epics (E1.3 HTTP server, E2 keys, …) plug their fx.Options into
// New via the functional-options pattern below.
package app

import (
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"

	"github.com/fenmoai/tempogate/api"
	"github.com/fenmoai/tempogate/cmd"
	"github.com/fenmoai/tempogate/config"
	"github.com/fenmoai/tempogate/log"
)

type appConfig struct {
	extra []fx.Option
}

type Option func(*appConfig)

// With appends an fx.Option to the composition root. Used by future modules
// (and by tests) to extend the graph without forking New.
func With(opts ...fx.Option) Option {
	return func(cfg *appConfig) { cfg.extra = append(cfg.extra, opts...) }
}

func New(opts ...Option) fx.Option {
	cfg := &appConfig{}
	for _, o := range opts {
		o(cfg)
	}
	base := []fx.Option{
		config.Fx(),
		log.Fx(),
		fx.WithLogger(func(l *zap.Logger) fxevent.Logger {
			return &fxevent.ZapLogger{Logger: l.WithOptions(zap.IncreaseLevel(zap.WarnLevel))}
		}),
		api.Fx(),
		cmd.Fx(),
	}
	return fx.Options(append(base, cfg.extra...)...)
}
