package admin

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"

	"github.com/fenmoai/tempogate/keys"
)

type keysParams struct {
	fx.In

	Registry KeyRegistry
	Signer   *keys.Signer
}

// newKeysRegistrar builds the /admin/keys handler over the KeyRegistry
// provided by state/sqlite's adapter and the Signer provided by keys.Fx, then
// returns its Register method as a Huma registrar. The result is fanned into
// the api package's "root_registrars" group so /admin/keys is pinned to the
// listener root regardless of an OIDC base path — under a /idp deployment
// the surface MUST stay at /admin/keys, never /idp/admin/keys.
func newKeysRegistrar(p keysParams) func(huma.API) {
	h := NewKeys(p.Registry, p.Signer)
	return h.Register
}

// Fx contributes the /admin/keys registrar into api's "root_registrars"
// group (root-pinned, not basePath-prefixed). KeyRegistry is satisfied by
// state/sqlite's adapter constructor (see state/sqlite/admin_adapter.go);
// the Signer is provided by keys.Fx.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				newKeysRegistrar,
				fx.ResultTags(`group:"root_registrars"`),
			),
		),
	)
}
