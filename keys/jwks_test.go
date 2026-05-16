package keys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type JWKSSuite struct {
	suite.Suite

	ctx   context.Context
	store *fakeKeyStore
	keys  *Keys
}

func TestJWKSSuite(t *testing.T) {
	suite.Run(t, new(JWKSSuite))
}

func (s *JWKSSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
	tick := 0
	clock := func() time.Time {
		t := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(tick) * time.Second)
		tick++
		return t
	}
	s.keys = New(WithStore(s.store), WithClock(clock), WithGenerateOptions(WithRSABits(2048)))
}

func (s *JWKSSuite) TestEmptyBeforeInit() {
	set, err := s.keys.PublicJWKS()
	s.Require().NoError(err)
	s.Empty(set)
}

func (s *JWKSSuite) TestProjectsLoadedKeypair() {
	s.Require().NoError(s.keys.Init(s.ctx))
	latest, err := s.keys.Latest()
	s.Require().NoError(err)

	set, err := s.keys.PublicJWKS()
	s.Require().NoError(err)
	s.Require().Len(set, 1)

	jwk := set[0]
	s.Equal(latest.Kid, jwk.Kid)
	s.Equal(AlgRS256, jwk.Alg)

	// n/e must reconstruct the exact public key encoded in the PEM.
	s.Equal(s.pubFromPEM(latest.PublicPEM), s.pubFromJWK(jwk))
}

func (s *JWKSSuite) TestExposesEveryKeyAfterRotation() {
	s.Require().NoError(s.keys.Init(s.ctx))
	oldKid := s.mustLatestKid()

	rotated, err := s.keys.Generate(s.ctx, true)
	s.Require().NoError(err)

	set, err := s.keys.PublicJWKS()
	s.Require().NoError(err)
	s.Require().Len(set, 2, "both keys must stay published so in-flight tokens still verify")
	s.Equal(oldKid, set[0].Kid)
	s.Equal(rotated.Kid, set[1].Kid)
}

func (s *JWKSSuite) TestRejectsNonRSAPublicPEM() {
	_, err := publicJWK(Keypair{
		Kid:       "bogus",
		Alg:       AlgRS256,
		PublicPEM: []byte("-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n"),
	})
	s.Require().Error(err)
}

func (s *JWKSSuite) mustLatestKid() string {
	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	return kp.Kid
}

func (s *JWKSSuite) pubFromPEM(pemBytes []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pemBytes)
	s.Require().NotNil(block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	s.Require().NoError(err)
	pub, ok := parsed.(*rsa.PublicKey)
	s.Require().True(ok)
	return pub
}

func (s *JWKSSuite) pubFromJWK(j JWK) *rsa.PublicKey {
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	s.Require().NoError(err)
	e, err := base64.RawURLEncoding.DecodeString(j.E)
	s.Require().NoError(err)
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}
}
