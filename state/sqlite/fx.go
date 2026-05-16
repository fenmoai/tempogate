package sqlite

import (
	"context"
	"time"

	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/keys"
	"github.com/fenmoai/tempogate/oidc"
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

// Fx registers the sqlite store as *Store (for direct callers like
// cmd/serve.go) plus every consumer-side interface it satisfies
// (keys.KeyStore, oidc.AuthRequestStore, oidc.CallbackStore, oidc.TokenStore),
// using a single underlying constructor.
func Fx() fx.Option {
	return fx.Provide(
		fx.Annotate(
			newFx,
			fx.As(new(keys.KeyStore)),
			fx.As(new(oidc.AuthRequestStore)),
			fx.As(new(oidc.CallbackStore)),
			fx.As(new(oidc.TokenStore)),
			fx.As(fx.Self()),
		),
	)
}
