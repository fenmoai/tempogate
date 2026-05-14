// Package app is the fx composition root for the tempogate binary.
//
// Subsequent epics (E1.2 config/log, E1.3 HTTP server, E2 keys, …) plug
// their fx.Options into New via the functional-options pattern below; today
// only the cobra dispatcher (cmd) is wired.
package app

import (
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/cmd"
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
	return fx.Options(append([]fx.Option{cmd.Fx()}, cfg.extra...)...)
}
