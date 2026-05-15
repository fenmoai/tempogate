package keys

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// fakeKeyStore is an in-memory keyStore that demonstrates the consumer-side
// test pattern: the interface is satisfied structurally inside the test file
// of the package that defines it.
type fakeKeyStore struct {
	mu  sync.Mutex
	kps []Keypair
}

func (s *fakeKeyStore) SaveKeypair(_ context.Context, kp Keypair) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kps = append(s.kps, kp)
	return nil
}

func (s *fakeKeyStore) LoadKeypairs(_ context.Context) ([]Keypair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Keypair, len(s.kps))
	copy(out, s.kps)
	return out, nil
}

var _ keyStore = (*fakeKeyStore)(nil)

type KeyStoreSuite struct {
	suite.Suite

	ctx   context.Context
	store keyStore
}

func TestKeyStoreSuite(t *testing.T) {
	suite.Run(t, new(KeyStoreSuite))
}

func (s *KeyStoreSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
}

func (s *KeyStoreSuite) TestRoundTrip() {
	now := time.Now().UTC()
	kp := func(kid string, offset time.Duration) Keypair {
		return Keypair{
			Kid:        kid,
			Alg:        "RS256",
			PrivatePEM: []byte("priv-" + kid),
			PublicPEM:  []byte("pub-" + kid),
			CreatedAt:  now.Add(offset),
		}
	}

	cases := []struct {
		name string
		save []Keypair
	}{
		{"empty store returns empty slice", nil},
		{"single keypair", []Keypair{kp("kid-1", 0)}},
		{"multiple keypairs preserve insertion order", []Keypair{
			kp("kid-1", 0),
			kp("kid-2", time.Second),
			kp("kid-3", 2*time.Second),
		}},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.SetupTest()

			for _, kp := range tc.save {
				s.Require().NoError(s.store.SaveKeypair(s.ctx, kp))
			}

			got, err := s.store.LoadKeypairs(s.ctx)
			s.Require().NoError(err)
			s.Require().Len(got, len(tc.save))
			for i, want := range tc.save {
				s.Equal(want, got[i])
			}
		})
	}
}

func (s *KeyStoreSuite) TestLoadReturnsCopy() {
	kp := Keypair{Kid: "kid-1", Alg: "RS256", CreatedAt: time.Now().UTC()}
	s.Require().NoError(s.store.SaveKeypair(s.ctx, kp))

	got, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(got, 1)

	got[0].Kid = "mutated"

	again, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(again, 1)
	s.Equal("kid-1", again[0].Kid)
}
