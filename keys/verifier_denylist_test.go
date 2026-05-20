package keys

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"
)

// VerifierDenylistSuite proves two things together:
//
//  1. A Verifier wired with a DenylistChecker rejects a token whose jti the
//     checker reports as revoked, returning ErrTokenRevoked.
//  2. A "mock Temporal" verifier — bare jwx jwt.Parse against the same JWKS
//     tempogate publishes, no denylist — STILL accepts the revoked token.
//     This documents the trade-off in code: Temporal's default ClaimMapper
//     has no revocation hook, so a revoked integration key keeps authorizing
//     Temporal gRPC until exp fires, while tempogate-mediated flows honor
//     the denylist immediately.
type VerifierDenylistSuite struct {
	suite.Suite

	ctx        context.Context
	store      *fakeKeyStore
	keys       *Keys
	signer     *Signer
	now        time.Time
	denylist   *stubDenylist
	withRevoke *Verifier
	noRevoke   *Verifier
}

func TestVerifierDenylistSuite(t *testing.T) {
	suite.Run(t, new(VerifierDenylistSuite))
}

func (s *VerifierDenylistSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
	s.now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	s.keys = New(WithStore(s.store), WithClock(s.kpClock()), withFastRSA())
	s.Require().NoError(s.keys.Init(s.ctx))

	s.signer = NewSigner(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithTokenClock(func() time.Time { return s.now }),
	)
	s.denylist = &stubDenylist{revoked: map[string]bool{}}
	s.withRevoke = NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Second) }),
		WithDenylist(s.denylist),
	)
	s.noRevoke = NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Second) }),
	)
}

func (s *VerifierDenylistSuite) kpClock() func() time.Time {
	tick := 0
	return func() time.Time {
		t := s.now.Add(time.Duration(tick) * time.Second)
		tick++
		return t
	}
}

func (s *VerifierDenylistSuite) mint() (string, string) {
	signed, jti, err := s.signer.Mint(s.ctx, MintRequest{
		Subject:     "svc-recon",
		Permissions: []string{"payments:worker"},
	})
	s.Require().NoError(err)
	return signed, jti
}

func (s *VerifierDenylistSuite) TestActiveTokenVerifies() {
	signed, _ := s.mint()
	_, err := s.withRevoke.Verify(s.ctx, signed)
	s.Require().NoError(err)
}

func (s *VerifierDenylistSuite) TestRevokedTokenRejectedWithErrTokenRevoked() {
	signed, jti := s.mint()
	s.denylist.revoked[jti] = true

	_, err := s.withRevoke.Verify(s.ctx, signed)
	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrTokenRevoked)
}

func (s *VerifierDenylistSuite) TestVerifierWithoutDenylistAcceptsRevokedToken() {
	// A verifier with no DenylistChecker (i.e. anything resembling
	// Temporal's default ClaimMapper) does not enforce revocation — the
	// same JWT the denylist-aware verifier rejected still verifies
	// cleanly here. Acts as a documented regression guard for the
	// stateless-JWT trade-off.
	signed, jti := s.mint()
	s.denylist.revoked[jti] = true

	tok, err := s.noRevoke.Verify(s.ctx, signed)
	s.Require().NoError(err, "verifier without denylist must not reject revoked tokens")
	got, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(jti, got)
}

func (s *VerifierDenylistSuite) TestMockTemporalJWKSVerifierAcceptsRevokedToken() {
	// Same documenting trade-off as above but against the exact verification
	// shape Temporal's frontend uses: jwx jwt.Parse with a JWKS built from
	// tempogate's published public keys, no app-layer denylist consultation.
	signed, jti := s.mint()
	s.denylist.revoked[jti] = true

	set := jwk.NewSet()
	for _, kp := range s.keys.All() {
		pub, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
		s.Require().NoError(err)
		s.Require().NoError(pub.Set(jwk.KeyIDKey, kp.Kid))
		s.Require().NoError(pub.Set(jwk.AlgorithmKey, jwa.RS256()))
		s.Require().NoError(set.AddKey(pub))
	}

	tok, err := jwt.Parse([]byte(signed),
		jwt.WithKeySet(set),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return s.now.Add(time.Second) })),
		jwt.WithIssuer("https://tempogate.test"),
	)
	s.Require().NoError(err, "a JWKS-only verifier (Temporal-style) must accept the revoked JWT — documents the stateless-JWT trade-off")
	gotJTI, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(jti, gotJTI)
}

func (s *VerifierDenylistSuite) TestDenylistErrorIsSurfacedNotSwallowed() {
	signed, _ := s.mint()
	boom := errors.New("storage on fire")
	v := NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Second) }),
		WithDenylist(&erroringDenylist{err: boom}),
	)
	_, err := v.Verify(s.ctx, signed)
	s.Require().Error(err)
	s.Require().ErrorIs(err, boom)
	s.NotErrorIs(err, ErrTokenRevoked,
		"a checker error must not look like a revoke — callers map ErrTokenRevoked to audit, others to 5xx")
}

// stubDenylist is a deterministic, in-memory DenylistChecker so the suite can
// flip a jti to revoked and back without touching sqlite.
type stubDenylist struct {
	revoked map[string]bool
}

func (s *stubDenylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	return s.revoked[jti], nil
}

type erroringDenylist struct{ err error }

func (e *erroringDenylist) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, e.err
}
