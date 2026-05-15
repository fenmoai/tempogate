package config

import (
	"time"

	xloadtype "github.com/gojekfarm/xtools/xload/type"
)

type Config struct {
	Log   LogConfig   `env:",prefix=LOG__"`
	HTTP  HTTPConfig  `env:",prefix=HTTP__"`
	State StateConfig `env:",prefix=STATE__"`
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
