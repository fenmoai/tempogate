package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"

	"github.com/fenmoai/tempogate/api"
	"github.com/fenmoai/tempogate/keys"
	"github.com/fenmoai/tempogate/oidc"
	"github.com/fenmoai/tempogate/oidc/google"
	"github.com/fenmoai/tempogate/state/sqlite"
)

// TokenE2ESuite exercises the whole authorization-code flow against the real
// HTTP surface: /authorize → (mock Google) → /callback/google → /token, with
// a real sqlite store, real signing keys, and the access token verified
// against the JWKS the server actually publishes. No fakes for the store,
// the signer, or the verification path.
type TokenE2ESuite struct {
	suite.Suite

	mg     *mockGoogle
	srv    *httptest.Server
	client *http.Client
}

func TestTokenE2ESuite(t *testing.T) {
	suite.Run(t, new(TokenE2ESuite))
}

func (s *TokenE2ESuite) SetupTest() {
	ctx := context.Background()

	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "e2e.db")))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(ctx))
	s.T().Cleanup(func() { _ = store.Close() })

	k := keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(k.Init(ctx))
	signer := keys.NewSigner(keys.WithKeys(k), keys.WithIssuer(testIssuer))

	s.mg = newMockGoogle(s.T(), testGoogleCID, "alice@example.com", true)
	upstream := google.New(
		s.mg.clientID,
		"mock-secret",
		s.mg.issuer()+"/token",
		testIssuer+oidc.CallbackPath,
		s.mg.issuer(),
	)

	reg, err := oidc.ParseClientRegistry("ui:https://app.example.com/auth")
	s.Require().NoError(err)

	authorizer := oidc.New(store, reg, testIssuer, testGoogleCID, s.mg.issuer()+"/auth")
	callback := oidc.NewCallback(store, upstream, "example.com")
	token := oidc.NewToken(store, signer)

	result := api.New(api.NewReadiness(),
		api.WithWellKnown(k, testIssuer),
		api.WithRegistrar(authorizer.Register),
		api.WithRegistrar(callback.Register),
		api.WithRegistrar(token.Register),
	)
	s.srv = httptest.NewServer(result.Handler)
	s.T().Cleanup(s.srv.Close)

	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// runFlow drives /authorize and /callback/google and returns the
// authorization code the browser would carry back to the downstream client.
func (s *TokenE2ESuite) runFlow() string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "ui")
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", "openid email")
	q.Set("state", "client-state-xyz")
	q.Set("code_challenge", pkceChallenge)
	q.Set("code_challenge_method", "S256")

	authResp, err := s.client.Get(s.srv.URL + "/authorize?" + q.Encode())
	s.Require().NoError(err)
	authResp.Body.Close()
	s.Require().Equal(http.StatusFound, authResp.StatusCode)

	toGoogle, err := url.Parse(authResp.Header.Get("Location"))
	s.Require().NoError(err)
	internalState := toGoogle.Query().Get("state")
	s.Require().NotEmpty(internalState)

	cbResp, err := s.client.Get(s.srv.URL + "/callback/google?code=real-google-code&state=" + internalState)
	s.Require().NoError(err)
	cbResp.Body.Close()
	s.Require().Equal(http.StatusFound, cbResp.StatusCode)

	backToClient, err := url.Parse(cbResp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("client-state-xyz", backToClient.Query().Get("state"))
	code := backToClient.Query().Get("code")
	s.Require().NotEmpty(code)
	return code
}

func (s *TokenE2ESuite) tokenRequest(form url.Values) *http.Response {
	resp, err := s.client.Post(s.srv.URL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	return resp
}

// jwksSet fetches the JWKS the server publishes and parses it into a key set
// usable for signature verification — the exact path a relying party
// (Temporal frontend) would take.
func (s *TokenE2ESuite) jwksSet() jwk.Set {
	resp, err := s.client.Get(s.srv.URL + "/.well-known/jwks.json")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	set, err := jwk.ParseReader(resp.Body)
	s.Require().NoError(err)
	s.Require().Positive(set.Len())
	return set
}

func (s *TokenE2ESuite) decode(resp *http.Response) struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
} {
	var b struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&b))
	return b
}

func (s *TokenE2ESuite) TestFullFlowMintsJWTVerifiableAgainstPublishedJWKS() {
	code := s.runFlow()

	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", pkceVerifier)

	resp := s.tokenRequest(f)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body := s.decode(resp)
	s.Equal("Bearer", body.TokenType)
	s.Equal(14400, body.ExpiresIn)
	s.Equal(body.AccessToken, body.IDToken)
	s.Require().NotEmpty(body.RefreshToken)

	tok, err := jwt.Parse([]byte(body.AccessToken),
		jwt.WithKeySet(s.jwksSet()),
		jwt.WithIssuer(testIssuer),
	)
	s.Require().NoError(err, "JWT must verify against the published JWKS")

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("alice@example.com", sub)

	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"*:admin"}, toStringSlice(s.T(), perms))

	exp, ok := tok.Expiration()
	s.Require().True(ok)
	iat, ok := tok.IssuedAt()
	s.Require().True(ok)
	s.InDelta(float64(4*time.Hour), float64(exp.Sub(iat)), float64(time.Second))

	// Refresh-token grant: a new, equally valid JWT against the same JWKS.
	rf := url.Values{}
	rf.Set("grant_type", "refresh_token")
	rf.Set("refresh_token", body.RefreshToken)
	rResp := s.tokenRequest(rf)
	defer rResp.Body.Close()
	s.Require().Equal(http.StatusOK, rResp.StatusCode)

	rBody := s.decode(rResp)
	s.NotEqual(body.RefreshToken, rBody.RefreshToken, "refresh token must rotate")
	rTok, err := jwt.Parse([]byte(rBody.AccessToken),
		jwt.WithKeySet(s.jwksSet()),
		jwt.WithIssuer(testIssuer),
	)
	s.Require().NoError(err)
	rPerms, ok := rTok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"*:admin"}, toStringSlice(s.T(), rPerms))
}

func (s *TokenE2ESuite) TestConsumedCodeCannotBeReplayed() {
	code := s.runFlow()
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", pkceVerifier)

	first := s.tokenRequest(f)
	first.Body.Close()
	s.Require().Equal(http.StatusOK, first.StatusCode)

	second := s.tokenRequest(f)
	defer second.Body.Close()
	s.Equal(http.StatusBadRequest, second.StatusCode)
}

func (s *TokenE2ESuite) TestPKCEMismatchRejectedEndToEnd() {
	code := s.runFlow()
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", "not-the-verifier-that-hashes-to-the-challenge")

	resp := s.tokenRequest(f)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}
