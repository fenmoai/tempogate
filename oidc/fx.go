package oidc

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/keys"
)

type authorizeParams struct {
	fx.In

	Store AuthRequestStore

	Issuer         string `name:"oidc_issuer"`
	Clients        string `name:"oidc_clients"`
	GoogleClientID string `name:"google_client_id"`
	GoogleAuth     string `name:"google_auth_endpoint"`
}

// newAuthorizeRegistrar builds the /authorize endpoint. A malformed
// OIDC__CLIENTS fails graph construction here rather than surfacing as a
// per-request error later.
func newAuthorizeRegistrar(p authorizeParams) (func(huma.API), error) {
	reg, err := ParseClientRegistry(p.Clients)
	if err != nil {
		return nil, err
	}
	a := New(p.Store, reg, p.Issuer, p.GoogleClientID, p.GoogleAuth)
	return a.Register, nil
}

type callbackParams struct {
	fx.In

	Store    CallbackStore
	Upstream Upstream

	AllowedDomains string `name:"oidc_allowed_domains"`
}

// newCallbackRegistrar builds the /callback/google endpoint. The Google
// upstream is injected as oidc.Upstream (bound by the oidc/google provider
// via fx.As), so this package never imports oauth2/go-oidc.
func newCallbackRegistrar(p callbackParams) func(huma.API) {
	c := NewCallback(p.Store, p.Upstream, p.AllowedDomains)
	return c.Register
}

type tokenParams struct {
	fx.In

	Store  TokenStore
	Signer *keys.Signer
}

// newTokenRegistrar builds the /token endpoint. The Signer is provided by
// keys.Fx over the shared keypair aggregate; TokenStore is satisfied by
// state/sqlite via fx.As.
func newTokenRegistrar(p tokenParams) func(huma.API) {
	t := NewToken(p.Store, p.Signer)
	return t.Register
}

// Fx contributes the /authorize, /callback/google and /token registrars into
// the shared "api_registrars" group the api package collects. The store,
// upstream and signer dependencies are satisfied by state/sqlite, oidc/google
// and keys via fx.As / fx.Provide.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				newAuthorizeRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
		fx.Provide(
			fx.Annotate(
				newCallbackRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
		fx.Provide(
			fx.Annotate(
				newTokenRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
	)
}
