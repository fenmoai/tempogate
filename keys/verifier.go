package keys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// ErrNoVerificationKeys is returned by Verify when the backing *Keys exposes
// no public keys to verify against.
var ErrNoVerificationKeys = errors.New("keys: verifier has no keys to verify against")

// Verifier validates tempogate-issued JWTs for tempogate's own needs (e.g.
// exchanging a refresh token). Temporal's gRPC frontend does not use this — it
// runs its own JWKS-backed verifier against /.well-known/jwks.json. Verifier
// exists so the parts of tempogate that consume their own tokens don't
// re-implement signature + claim checks inconsistently with the Signer.
type Verifier struct {
	keys     *Keys
	issuer   string
	audience string
	now      func() time.Time
}

func NewVerifier(opts ...TokenOption) *Verifier {
	c := newTokenConfig(opts...)
	return &Verifier{
		keys:     c.keys,
		issuer:   c.issuer,
		audience: c.audience,
		now:      c.now,
	}
}

// Verify checks the signature against every loaded public key (kid-matched, so
// a token minted before a --force rotation still verifies while its key is
// retained) and enforces the temporal claims plus the configured iss/aud. It
// returns the parsed token so callers can read sub/permissions/jti.
//
// ctx mirrors Signer.Mint for symmetry; verification is synchronous against
// the in-memory key cache.
func (v *Verifier) Verify(_ context.Context, raw string) (jwt.Token, error) {
	if v.keys == nil {
		return nil, ErrNoVerificationKeys
	}

	set := jwk.NewSet()
	for _, kp := range v.keys.All() {
		pub, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
		if err != nil {
			return nil, fmt.Errorf("keys: parse public key (kid=%s): %w", kp.Kid, err)
		}
		if err := pub.Set(jwk.KeyIDKey, kp.Kid); err != nil {
			return nil, fmt.Errorf("keys: set kid: %w", err)
		}
		if err := pub.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			return nil, fmt.Errorf("keys: set alg: %w", err)
		}
		if err := set.AddKey(pub); err != nil {
			return nil, fmt.Errorf("keys: add key to set (kid=%s): %w", kp.Kid, err)
		}
	}
	if set.Len() == 0 {
		return nil, ErrNoVerificationKeys
	}

	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(set),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	}
	if v.issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(v.audience))
	}

	tok, err := jwt.Parse([]byte(raw), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("keys: verify token: %w", err)
	}
	return tok, nil
}
