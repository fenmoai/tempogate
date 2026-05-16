package config

import (
	"time"

	xloadtype "github.com/gojekfarm/xtools/xload/type"
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/log"
)

// Result projects narrow values out of *Config so downstream packages can
// depend on the specific thing they need (log level, http listener) rather
// than the whole config struct.
type Result struct {
	fx.Out

	LogLevel          log.Level
	HTTPListener      xloadtype.Listener `name:"http"`
	SqlitePath        string             `name:"sqlite_path"`
	SqliteMaxConns    int                `name:"sqlite_max_conns"`
	SqliteBusyTimeout time.Duration      `name:"sqlite_busy_timeout"`
	OIDCIssuer        string             `name:"oidc_issuer"`
}

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(New),
		fx.Provide(func(cfg *Config) Result {
			return Result{
				LogLevel:          log.Level(cfg.Log.Level),
				HTTPListener:      cfg.HTTP.Listener,
				SqlitePath:        cfg.State.Sqlite.Path,
				SqliteMaxConns:    cfg.State.Sqlite.MaxConns,
				SqliteBusyTimeout: cfg.State.Sqlite.BusyTimeout,
				OIDCIssuer:        cfg.OIDC.Issuer,
			}
		}),
	)
}
