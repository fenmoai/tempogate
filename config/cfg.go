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

// OIDCConfig carries the externally reachable identity of this server and the
// upstream Google IdP it federates to. Issuer is the base URL relying parties
// (Temporal Web UI, frontend) use to reach tempogate; the discovery doc's
// jwks_uri is derived from it.
type OIDCConfig struct {
	Issuer string `env:"ISSUER"`

	// Clients is the v1 client registry: a comma-separated list of
	// "id:redirect_uri_prefix" entries. The first ':' splits id from prefix,
	// so the prefix may itself contain a scheme (e.g. "ui:https://x/cb").
	Clients string `env:"CLIENTS"`

	Google GoogleConfig `env:",prefix=GOOGLE__"`
}

// GoogleConfig is the upstream OAuth2 client tempogate uses against Google.
// AuthEndpoint is overridable so the end-to-end test can point at a mock IdP.
type GoogleConfig struct {
	ClientID     string `env:"CLIENT_ID"`
	AuthEndpoint string `env:"AUTH_ENDPOINT"`
}
