package config

import (
	"net"
	"testing"
	"time"

	xloadtype "github.com/gojekfarm/xtools/xload/type"
	"github.com/stretchr/testify/suite"
)

type ConfigSuite struct {
	suite.Suite
}

func TestConfigSuite(t *testing.T) {
	suite.Run(t, new(ConfigSuite))
}

func (s *ConfigSuite) TestNew() {
	cases := []struct {
		name string
		env  map[string]string
		want *Config
	}{
		{
			name: "defaults",
			want: &Config{
				Log: LogConfig{Level: "info"},
				HTTP: HTTPConfig{
					Listener: xloadtype.Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
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
					Google: GoogleConfig{AuthEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"},
				},
			},
		},
		{
			name: "log and http overridden by env",
			env: map[string]string{
				"LOG__LEVEL":     "debug",
				"HTTP__LISTENER": "0.0.0.0:9000",
			},
			want: &Config{
				Log: LogConfig{Level: "debug"},
				HTTP: HTTPConfig{
					Listener: xloadtype.Listener{
						IP:   net.IPv4(0, 0, 0, 0),
						Port: 9000,
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
					Google: GoogleConfig{AuthEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"},
				},
			},
		},
		{
			name: "sqlite overridden by env",
			env: map[string]string{
				"STATE__SQLITE__PATH":         "/tmp/tempogate.db",
				"STATE__SQLITE__MAX_CONNS":    "8",
				"STATE__SQLITE__BUSY_TIMEOUT": "2s",
			},
			want: &Config{
				Log: LogConfig{Level: "info"},
				HTTP: HTTPConfig{
					Listener: xloadtype.Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
				},
				State: StateConfig{
					Sqlite: SqliteConfig{
						Path:        "/tmp/tempogate.db",
						MaxConns:    8,
						BusyTimeout: 2 * time.Second,
					},
				},
				OIDC: OIDCConfig{
					Issuer: "http://127.0.0.1:8000",
					Google: GoogleConfig{AuthEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"},
				},
			},
		},
		{
			name: "oidc issuer overridden by env",
			env: map[string]string{
				"OIDC__ISSUER": "https://tempogate.internal.example.com",
			},
			want: &Config{
				Log: LogConfig{Level: "info"},
				HTTP: HTTPConfig{
					Listener: xloadtype.Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
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
					Issuer: "https://tempogate.internal.example.com",
					Google: GoogleConfig{AuthEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"},
				},
			},
		},
		{
			name: "oidc clients and google overridden by env",
			env: map[string]string{
				"OIDC__CLIENTS":               "ui:https://temporal.example.com/auth/sso/callback,cli:http://127.0.0.1",
				"OIDC__GOOGLE__CLIENT_ID":     "google-client-123.apps.googleusercontent.com",
				"OIDC__GOOGLE__AUTH_ENDPOINT": "http://127.0.0.1:9999/mock/auth",
			},
			want: &Config{
				Log: LogConfig{Level: "info"},
				HTTP: HTTPConfig{
					Listener: xloadtype.Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
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
					Issuer:  "http://127.0.0.1:8000",
					Clients: "ui:https://temporal.example.com/auth/sso/callback,cli:http://127.0.0.1",
					Google: GoogleConfig{
						ClientID:     "google-client-123.apps.googleusercontent.com",
						AuthEndpoint: "http://127.0.0.1:9999/mock/auth",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			for k, v := range tc.env {
				s.T().Setenv(k, v)
			}

			got, err := New(Params{})
			s.Require().NoError(err)
			s.Equal(tc.want, got)
		})
	}
}
