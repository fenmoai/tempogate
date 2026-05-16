package oidc

import (
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"
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

	Store CallbackStore

	Issuer              string `name:"oidc_issuer"`
	AllowedDomains      string `name:"oidc_allowed_domains"`
	GoogleClientID      string `name:"google_client_id"`
	GoogleClientSecret  string `name:"google_client_secret"`
	GoogleTokenEndpoint string `name:"google_token_endpoint"`
	GoogleIssuerURL     string `name:"google_issuer_url"`
}

// newCallbackRegistrar builds the /callback/google endpoint. The Google
// upstream's OIDC discovery is lazy, so nothing here touches the network at
// graph-construction time.
func newCallbackRegistrar(p callbackParams) func(huma.API) {
	redirectURL := strings.TrimRight(p.Issuer, "/") + callbackPath
	up := NewGoogleUpstream(
		p.GoogleClientID,
		p.GoogleClientSecret,
		p.GoogleTokenEndpoint,
		redirectURL,
		p.GoogleIssuerURL,
	)
	c := NewCallback(p.Store, up, p.AllowedDomains)
	return c.Register
}

// Fx contributes the /authorize and /callback/google registrars into the
// shared "api_registrars" group the api package collects. The store
// dependencies are satisfied by state/sqlite via fx.As.
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
	)
}
