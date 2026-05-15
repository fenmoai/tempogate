package sqlite

import (
	"context"
	"time"

	"go.uber.org/fx"
)

type Params struct {
	fx.In

	Lifecycle fx.Lifecycle

	Path        string        `name:"sqlite_path"`
	MaxConns    int           `name:"sqlite_max_conns"`
	BusyTimeout time.Duration `name:"sqlite_busy_timeout"`
}

func newFx(p Params) (*Store, error) {
	s, err := New(
		WithPath(p.Path),
		WithMaxConns(p.MaxConns),
		WithBusyTimeout(p.BusyTimeout),
	)
	if err != nil {
		return nil, err
	}

	p.Lifecycle.Append(fx.Hook{
		OnStop: func(_ context.Context) error { return s.Close() },
	})
	return s, nil
}

func Fx() fx.Option { return fx.Provide(newFx) }
