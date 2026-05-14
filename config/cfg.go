package config

import xloadtype "github.com/gojekfarm/xtools/xload/type"

type Config struct {
	Log  LogConfig  `env:",prefix=LOG__"`
	HTTP HTTPConfig `env:",prefix=HTTP__"`
}

type LogConfig struct {
	Level string `env:"LEVEL"`
}

type HTTPConfig struct {
	Listener xloadtype.Listener `env:"LISTENER"`
}
