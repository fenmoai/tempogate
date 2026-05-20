package config

import (
	"time"

	xloadtype "github.com/gojekfarm/xtools/xload/type"
)

type Config struct {
	Log   LogConfig   `env:",prefix=LOG__"`
	HTTP  HTTPConfig  `env:",prefix=HTTP__"`
	Admin AdminConfig `env:",prefix=ADMIN__"`
	State StateConfig `env:",prefix=STATE__"`
	OIDC  OIDCConfig  `env:",prefix=OIDC__"`
}

type LogConfig struct {
	Level string `env:"LEVEL"`
}

type HTTPConfig struct {
	Listener xloadtype.Listener `env:"LISTENER"`
}

// AdminConfig configures the private admin listener. It is intentionally a
// separate bind from HTTPConfig: the admin Huma API is mounted on its own
// http.Server so the public listener never has handlers for /admin/*. Defaults
// to a loopback bind so a mis-deployment fails closed (admin unreachable from
// the pod's service IP unless explicitly opted into a cluster-internal bind).
type AdminConfig struct {
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
	// Every client declared here is public: PKCE is mandatory.
	Clients string `env:"CLIENTS"`

	// ClientSecrets is the deliberately-separate opt-in for the confidential
	// PKCE carve-out: a comma-separated list of "id:secret" for clients in
	// Clients that authenticate at /token with a shared secret and do not
	// implement PKCE (e.g. the Temporal Web UI). Keeping it out of CLIENTS
	// makes the relaxation explicit and auditable; an entry for an
	// unregistered id fails fast. Empty ⇒ every client stays public. See
	// docs/pkce-and-confidential-clients.md.
	ClientSecrets string `env:"CLIENT_SECRETS"`

	// AllowedDomains is the v1 flat-authz gate: a comma-separated list of
	// email domains (e.g. "example.com,corp.example.org"). The callback
	// admits a Google identity only when its email domain matches one of
	// these exactly. Empty means no one is allowed.
	AllowedDomains string `env:"ALLOWED_DOMAINS"`

	Google GoogleConfig `env:",prefix=GOOGLE__"`
}

// GoogleConfig is the upstream OAuth2/OIDC client tempogate uses against
// Google. AuthEndpoint, TokenEndpoint and IssuerURL are all overridable so
// the end-to-end test can point the whole flow at a mock IdP.
type GoogleConfig struct {
	ClientID     string `env:"CLIENT_ID"`
	ClientSecret string `env:"CLIENT_SECRET"`
	AuthEndpoint string `env:"AUTH_ENDPOINT"`

	// TokenEndpoint is where the callback exchanges the authorization code
	// for Google's id_token.
	TokenEndpoint string `env:"TOKEN_ENDPOINT"`

	// IssuerURL is the expected `iss` of Google's id_token and the base for
	// OIDC discovery (JWKS). The callback verifies the id_token signature
	// against the JWKS published under this issuer.
	IssuerURL string `env:"ISSUER_URL"`
}
