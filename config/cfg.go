package config

import (
	"time"

	xloadtype "github.com/gojekfarm/xtools/xload/type"
)

type Config struct {
	Log   LogConfig   `env:",prefix=LOG__"`
	HTTP  HTTPConfig  `env:",prefix=HTTP__"`
	State StateConfig `env:",prefix=STATE__"`
	OIDC  OIDCConfig  `env:",prefix=OIDC__"`
}

type LogConfig struct {
	Level string `env:"LEVEL"`
}

type HTTPConfig struct {
	Listener xloadtype.Listener `env:"LISTENER"`
}

type StateConfig struct {
	Sqlite SqliteConfig `env:",prefix=SQLITE__"`
}

type SqliteConfig struct {
	Path        string        `env:"PATH"`
	MaxConns    int           `env:"MAX_CONNS"`
	BusyTimeout time.Duration `env:"BUSY_TIMEOUT"`
}

// OIDCConfig carries the externally reachable identity of this server. Issuer
// is the base URL relying parties (Temporal Web UI, frontend) use to reach
// tempogate; the discovery doc's jwks_uri is derived from it.
type OIDCConfig struct {
	Issuer string `env:"ISSUER"`
}
