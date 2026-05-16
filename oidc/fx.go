package oidc

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"
)

type fxParams struct {
	fx.In

	Store AuthRequestStore

	Issuer         string `name:"oidc_issuer"`
	Clients        string `name:"oidc_clients"`
	GoogleClientID string `name:"google_client_id"`
	GoogleAuth     string `name:"google_auth_endpoint"`
}

// newRegistrar builds the authorize endpoint and exposes it as an api
// registrar. A malformed OIDC__CLIENTS fails graph construction here rather
// than surfacing as a per-request error later.
func newRegistrar(p fxParams) (func(huma.API), error) {
	reg, err := ParseClientRegistry(p.Clients)
	if err != nil {
		return nil, err
	}
	a := New(p.Store, reg, p.Issuer, p.GoogleClientID, p.GoogleAuth)
	return a.Register, nil
}

// Fx contributes the /authorize registrar into the shared "api_registrars"
// group the api package collects. The AuthRequestStore dependency is
// satisfied by state/sqlite via fx.As(new(oidc.AuthRequestStore)).
func Fx() fx.Option {
	return fx.Provide(
		fx.Annotate(
			newRegistrar,
			fx.ResultTags(`group:"api_registrars"`),
		),
	)
}
