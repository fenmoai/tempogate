package keys

import "go.uber.org/fx"

type fxParams struct {
	fx.In

	Store KeyStore
}

func newFx(p fxParams) *Keys {
	return New(WithStore(p.Store))
}

// Fx wires *Keys into the composition root. The KeyStore dependency is
// satisfied by state/sqlite via fx.Annotate(..., fx.As(new(keys.KeyStore))).
func Fx() fx.Option { return fx.Provide(newFx) }
