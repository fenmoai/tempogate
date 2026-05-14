package config

import (
	"net"

	xloadtype "github.com/gojekfarm/xtools/xload/type"
)

func defaultConfig() *Config {
	return &Config{
		Log: LogConfig{Level: "info"},
		HTTP: HTTPConfig{
			Listener: xloadtype.Listener{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 8000,
			},
		},
	}
}
