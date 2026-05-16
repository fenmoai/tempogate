package keys

import "go.uber.org/fx"

type fxParams struct {
	fx.In

	Store KeyStore
}

func newFx(p fxParams) *Keys {
	return New(WithStore(p.Store))
}

type signerParams struct {
	fx.In

	Keys *Keys

	Issuer string `name:"oidc_issuer"`
}

// newSigner wires the JWT-minting Signer over the keypair aggregate. The
// issuer it stamps is the same value the OIDC discovery document advertises,
// so a relying party that fetched discovery sees a matching `iss`. Audience
// is intentionally unset in v1: Temporal's default claim mapper does not
// enforce `aud`, and leaving it empty avoids minting a claim no verifier
// checks.
func newSigner(p signerParams) *Signer {
	return NewSigner(WithKeys(p.Keys), WithIssuer(p.Issuer))
}

// Fx wires *Keys and the *Signer over it into the composition root. The
// KeyStore dependency is satisfied by state/sqlite via
// fx.Annotate(..., fx.As(new(keys.KeyStore))); oidc_issuer is contributed by
// config.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newFx),
		fx.Provide(newSigner),
	)
}
