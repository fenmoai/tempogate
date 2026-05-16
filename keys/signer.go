package keys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// ErrNoSigningKeys is returned by Mint when the backing *Keys has no keypair
// loaded (Init/Generate was never called, or the store is empty).
var ErrNoSigningKeys = errors.New("keys: signer has no keypair to sign with")

// permissionsClaim is Temporal's default JWT ClaimMapper contract: a flat
// []string of "<namespace>:<action>" (plus "system:<role>") entries. emailClaim
// is the OIDC-standard end-user identifier; tempogate carries it for human
// tokens so downstream audit can attribute actions without a second lookup.
const (
	permissionsClaim = "permissions"
	emailClaim       = "email"
)

// tokenConfig is the shared construction state for Signer and Verifier: both
// agree on the issuer/audience pair and read keypairs from the same *Keys, so
// a single functional-option set keeps the two halves from drifting.
type tokenConfig struct {
	keys     *Keys
	issuer   string
	audience string
	now      func() time.Time
}

// TokenOption configures a Signer or a Verifier. It is distinct from the
// package-level Option (which configures the *Keys aggregate) so the two
// option spaces don't collide.
type TokenOption func(*tokenConfig)

// WithKeys supplies the keypair aggregate. The Signer signs with Latest(); the
// Verifier matches the token's kid against every public key the aggregate holds
// so verification survives a --force rotation.
func WithKeys(k *Keys) TokenOption {
	return func(c *tokenConfig) { c.keys = k }
}

// WithIssuer sets the iss claim the Signer stamps and the Verifier enforces.
// Empty issuer ⇒ the claim is neither written nor checked.
func WithIssuer(url string) TokenOption {
	return func(c *tokenConfig) { c.issuer = url }
}

// WithAudience sets the aud claim the Signer stamps and the Verifier enforces.
// Empty audience ⇒ the claim is neither written nor checked.
func WithAudience(aud string) TokenOption {
	return func(c *tokenConfig) { c.audience = aud }
}

// WithTokenClock swaps the clock used to stamp iat/nbf/exp (Signer) and to
// evaluate temporal claims (Verifier). Intended for tests.
//
// This is deliberately not named WithClock: the package already exports
// WithClock for the *Keys keypair-stamping clock, which is a different concern
// (when a keypair was created vs. when a token was issued).
func WithTokenClock(now func() time.Time) TokenOption {
	return func(c *tokenConfig) { c.now = now }
}

func newTokenConfig(opts ...TokenOption) tokenConfig {
	c := tokenConfig{now: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Signer mints tempogate-issued JWTs. It is the shared primitive behind human
// token exchange, the CLI loopback token, and admin integration keys; the
// claim shape is uniform so Temporal's default ClaimMapper sees the same token
// regardless of which flow produced it.
type Signer struct {
	keys     *Keys
	issuer   string
	audience string
	now      func() time.Time
}

func NewSigner(opts ...TokenOption) *Signer {
	c := newTokenConfig(opts...)
	return &Signer{
		keys:     c.keys,
		issuer:   c.issuer,
		audience: c.audience,
		now:      c.now,
	}
}

// MintRequest is the per-token input. Permissions must already be in Temporal's
// "<namespace>:<action>" form (the caller owns that mapping). A zero TTL mints
// a token with no exp claim — appropriate for long-lived integration keys whose
// lifetime is governed by revocation, not expiry.
type MintRequest struct {
	Subject     string
	Permissions []string
	TTL         time.Duration
	Email       string
}

// Mint builds, signs, and serializes a JWT for req. It returns the compact
// serialization and the token's jti (a UUIDv7, so jti ordering tracks issue
// time) for callers that persist a token registry or refresh-token mapping.
//
// ctx is accepted for signature stability with the future key-fetch path; the
// current in-memory keypair cache makes signing synchronous.
func (s *Signer) Mint(_ context.Context, req MintRequest) (string, string, error) {
	if s.keys == nil {
		return "", "", ErrNoSigningKeys
	}
	kp, err := s.keys.Latest()
	if err != nil {
		return "", "", err
	}

	privKey, err := jwk.ParseKey(kp.PrivatePEM, jwk.WithX509(true))
	if err != nil {
		return "", "", fmt.Errorf("keys: parse private key (kid=%s): %w", kp.Kid, err)
	}
	// jwx copies kid+alg from the signing key into the JWS protected header,
	// which is what lets relying parties pick the right JWKS entry.
	if err := privKey.Set(jwk.KeyIDKey, kp.Kid); err != nil {
		return "", "", fmt.Errorf("keys: set kid: %w", err)
	}
	if err := privKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return "", "", fmt.Errorf("keys: set alg: %w", err)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return "", "", fmt.Errorf("keys: generate jti: %w", err)
	}
	jti := id.String()

	now := s.now()
	b := jwt.NewBuilder().
		Subject(req.Subject).
		IssuedAt(now).
		NotBefore(now).
		JwtID(jti).
		Claim(permissionsClaim, req.Permissions)
	if s.issuer != "" {
		b.Issuer(s.issuer)
	}
	if s.audience != "" {
		b.Audience([]string{s.audience})
	}
	if req.TTL > 0 {
		b.Expiration(now.Add(req.TTL))
	}
	if req.Email != "" {
		b.Claim(emailClaim, req.Email)
	}

	tok, err := b.Build()
	if err != nil {
		return "", "", fmt.Errorf("keys: build token: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey))
	if err != nil {
		return "", "", fmt.Errorf("keys: sign token: %w", err)
	}
	return string(signed), jti, nil
}
