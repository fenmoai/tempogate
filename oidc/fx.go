package oidc

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/keys"
)

type clientRegistryParams struct {
	fx.In

	Clients string `name:"oidc_clients"`
	Secrets string `name:"oidc_client_secrets"`
}

// newClientRegistry parses the single shared ClientRegistry both /authorize
// and /token depend on. A malformed OIDC__CLIENTS or OIDC__CLIENT_SECRETS —
// or a secret declared for an unregistered client — fails graph construction
// here rather than surfacing as a per-request error later, so the PKCE
// carve-out can never be half-configured at runtime.
func newClientRegistry(p clientRegistryParams) (ClientRegistry, error) {
	reg, err := ParseClientRegistry(p.Clients)
	if err != nil {
		return nil, err
	}
	if err := reg.WithSecrets(p.Secrets); err != nil {
		return nil, err
	}
	return reg, nil
}

type authorizeParams struct {
	fx.In

	Store   AuthRequestStore
	Clients ClientRegistry

	Issuer         string `name:"oidc_issuer"`
	GoogleClientID string `name:"google_client_id"`
	GoogleAuth     string `name:"google_auth_endpoint"`
}

// newAuthorizeRegistrar builds the /authorize endpoint over the shared
// registry, so its PKCE/confidential decisions cannot drift from /token's.
func newAuthorizeRegistrar(p authorizeParams) func(huma.API) {
	a := New(p.Store, p.Clients, p.Issuer, p.GoogleClientID, p.GoogleAuth)
	return a.Register
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

	Store   TokenStore
	Signer  *keys.Signer
	Clients ClientRegistry
}

// newTokenRegistrar builds the /token endpoint. The Signer is provided by
// keys.Fx over the shared keypair aggregate; TokenStore is satisfied by
// state/sqlite via fx.As; ClientRegistry is the same instance /authorize
// uses, so a code minted without PKCE is redeemable only by the confidential
// client that secret-authenticates here.
func newTokenRegistrar(p tokenParams) func(huma.API) {
	t := NewToken(p.Store, p.Signer, p.Clients)
	return t.Register
}

type userInfoParams struct {
	fx.In

	Verifier *keys.Verifier
}

// newUserInfoRegistrar builds the /userinfo endpoint. The Verifier is
// provided by keys.Fx over the same keypair aggregate the Signer uses, so a
// token minted by /token verifies here.
func newUserInfoRegistrar(p userInfoParams) func(huma.API) {
	u := NewUserInfo(p.Verifier)
	return u.Register
}

// Fx contributes the /authorize, /callback/google, /token and /userinfo
// registrars into the shared "api_registrars" group the api package collects.
// The store, upstream, signer and verifier dependencies are satisfied by
// state/sqlite, oidc/google and keys via fx.As / fx.Provide.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newClientRegistry),
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
		fx.Provide(
			fx.Annotate(
				newUserInfoRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
	)
}
