package config

import (
	"net"
	"time"

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
		Admin: AdminConfig{
			Listener: xloadtype.Listener{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 8081,
			},
		},
		State: StateConfig{
			Sqlite: SqliteConfig{
				Path:        "/var/lib/tempogate/state.db",
				MaxConns:    1,
				BusyTimeout: 5 * time.Second,
			},
		},
		OIDC: OIDCConfig{
			Issuer: "http://127.0.0.1:8000",
			Google: GoogleConfig{
				AuthEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
				// #nosec G101 -- public Google token endpoint URL, not a
				// credential; G101 trips on the "Token" in the field name.
				TokenEndpoint: "https://oauth2.googleapis.com/token",
				IssuerURL:     "https://accounts.google.com",
			},
		},
	}
}
