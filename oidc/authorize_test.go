package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/fenmoai/tempogate/oidc"
)

const (
	testIssuer      = "https://tempogate.example.com"
	testGoogleAuth  = "https://accounts.google.com/o/oauth2/v2/auth"
	testGoogleCID   = "google-client-123.apps.googleusercontent.com"
	testRedirectURI = "https://app.example.com/auth/callback"
	fixedState      = "fixed-internal-state"
)

var fixedNow = time.Unix(1700000000, 0).UTC()

// memAuthStore satisfies oidc.AuthRequestStore structurally — the
// consumer-side interface convention means oidc_test owns its own stub.
type memAuthStore struct {
	mu      sync.Mutex
	saved   []oidc.AuthRequest
	saveErr error
}

func (m *memAuthStore) SaveAuthRequest(_ context.Context, ar oidc.AuthRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = append(m.saved, ar)
	return nil
}

func (m *memAuthStore) only() oidc.AuthRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saved[len(m.saved)-1]
}

func (m *memAuthStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.saved)
}

type AuthorizeSuite struct {
	suite.Suite

	store  *memAuthStore
	srv    *httptest.Server
	client *http.Client
}

func TestAuthorizeSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeSuite))
}

func (s *AuthorizeSuite) SetupTest() {
	s.store = &memAuthStore{}
	s.srv = s.serverFor(s.store,
		oidc.WithClock(func() time.Time { return fixedNow }),
		oidc.WithStateGenerator(func() (string, error) { return fixedState, nil }),
	)
	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *AuthorizeSuite) TearDownTest() {
	s.srv.Close()
}

func (s *AuthorizeSuite) serverFor(store oidc.AuthRequestStore, opts ...oidc.Option) *httptest.Server {
	reg, err := oidc.ParseClientRegistry("ui:https://app.example.com/auth,cli:http://127.0.0.1")
	s.Require().NoError(err)

	a := oidc.New(store, reg, testIssuer, testGoogleCID, testGoogleAuth, opts...)

	mux := http.NewServeMux()
	a.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	return httptest.NewServer(mux)
}

func (s *AuthorizeSuite) get(srv *httptest.Server, q url.Values) *http.Response {
	resp, err := s.client.Get(srv.URL + "/authorize?" + q.Encode())
	s.Require().NoError(err)
	return resp
}

func validParams() url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "ui")
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", "openid email")
	q.Set("state", "client-state-abc")
	q.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	q.Set("code_challenge_method", "S256")
	return q
}

func (s *AuthorizeSuite) TestValidRequestRedirectsToGoogle() {
	resp := s.get(s.srv, validParams())
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("accounts.google.com", loc.Host)
	s.Equal("/o/oauth2/v2/auth", loc.Path)

	q := loc.Query()
	s.Equal(testGoogleCID, q.Get("client_id"))
	s.Equal(testIssuer+"/callback/google", q.Get("redirect_uri"))
	s.Equal("code", q.Get("response_type"))
	s.Equal("openid email", q.Get("scope"))
	s.Equal(fixedState, q.Get("state"))
}

func (s *AuthorizeSuite) TestValidRequestPersistsAuthRequestWithTTL() {
	resp := s.get(s.srv, validParams())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Equal(1, s.store.count())

	ar := s.store.only()
	s.Equal(fixedState, ar.InternalState)
	s.Equal("ui", ar.ClientID)
	s.Equal(testRedirectURI, ar.RedirectURI)
	s.Equal("openid email", ar.Scope)
	s.Equal("client-state-abc", ar.ClientState)
	s.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", ar.CodeChallenge)
	s.Equal("S256", ar.CodeChallengeMethod)
	s.True(fixedNow.Equal(ar.CreatedAt))
	s.Equal(5*time.Minute, ar.ExpiresAt.Sub(ar.CreatedAt))
}

func (s *AuthorizeSuite) TestInvalidRequestsReturnOAuth2Errors() {
	cases := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{
			name:      "unknown client_id",
			mutate:    func(q url.Values) { q.Set("client_id", "ghost") },
			wantError: "invalid_client",
		},
		{
			name:      "redirect_uri outside registered prefix",
			mutate:    func(q url.Values) { q.Set("redirect_uri", "https://evil.example.com/cb") },
			wantError: "invalid_request",
		},
		{
			name:      "unsupported response_type",
			mutate:    func(q url.Values) { q.Set("response_type", "token") },
			wantError: "unsupported_response_type",
		},
		{
			name:      "scope missing openid",
			mutate:    func(q url.Values) { q.Set("scope", "email profile") },
			wantError: "invalid_scope",
		},
		{
			name:      "missing code_challenge (PKCE required)",
			mutate:    func(q url.Values) { q.Del("code_challenge") },
			wantError: "invalid_request",
		},
		{
			name:      "code_challenge_method not S256",
			mutate:    func(q url.Values) { q.Set("code_challenge_method", "plain") },
			wantError: "invalid_request",
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			q := validParams()
			tc.mutate(q)

			resp := s.get(s.srv, q)
			defer resp.Body.Close()

			s.Equal(http.StatusBadRequest, resp.StatusCode)

			var body struct {
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
			s.Equal(tc.wantError, body.Error)
			s.NotEmpty(body.Desc)
			s.Empty(resp.Header.Get("Location"))
			s.Zero(s.store.count())
		})
	}
}

func (s *AuthorizeSuite) TestStorePersistFailureIsServerError() {
	store := &memAuthStore{saveErr: errors.New("boom")}
	srv := s.serverFor(store,
		oidc.WithClock(func() time.Time { return fixedNow }),
		oidc.WithStateGenerator(func() (string, error) { return fixedState, nil }),
	)
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Zero(store.count())
}

func (s *AuthorizeSuite) TestDefaultStateGeneratorProducesOpaqueState() {
	store := &memAuthStore{}
	srv := s.serverFor(store) // no WithStateGenerator: exercises crypto/rand path
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	state := loc.Query().Get("state")

	raw, err := base64.RawURLEncoding.DecodeString(state)
	s.Require().NoError(err)
	s.Len(raw, 32)
	s.Equal(state, store.only().InternalState)
}

func (s *AuthorizeSuite) TestMalformedGoogleEndpointIsServerError() {
	reg, err := oidc.ParseClientRegistry("ui:https://app.example.com/auth")
	s.Require().NoError(err)
	a := oidc.New(&memAuthStore{}, reg, testIssuer, testGoogleCID, "http://%zz/bad")

	mux := http.NewServeMux()
	a.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

func (s *AuthorizeSuite) TestStateGeneratorFailureIsServerError() {
	store := &memAuthStore{}
	srv := s.serverFor(store,
		oidc.WithStateGenerator(func() (string, error) {
			return "", errors.New("no entropy")
		}),
	)
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Zero(store.count())
}
