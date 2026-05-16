package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/fenmoai/tempogate/keys"
)

const (
	tokenPath = "/token"

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"

	// accessTokenTTL is the lifetime of a minted access/id token. Short
	// enough that a leaked token has a bounded blast radius; the refresh
	// token covers continuity.
	accessTokenTTL = 4 * time.Hour

	// refreshTokenTTL bounds how long a session can be silently resumed
	// without a fresh Google round-trip.
	refreshTokenTTL = 30 * 24 * time.Hour

	refreshEntropyBytes = 32
)

// ErrRefreshNotFound is returned by ConsumeRefresh when no token matches —
// because it was never issued, has already been used (single-use; refresh is
// rotated on every exchange), or its row was reaped. The /token handler maps
// this to OAuth2 invalid_grant.
var ErrRefreshNotFound = errors.New("oidc: refresh token not found")

// Refresh is the opaque, single-use credential a client presents to obtain a
// fresh access token without another Google round-trip. Token is the random
// secret the client holds; JTI references the access token minted alongside
// it, so an operator can correlate a refresh row with the JWT it renewed.
// Each exchange consumes the row and mints a new one (rotation), so a
// captured refresh token is usable at most once before it is invalidated by
// the legitimate client's next refresh.
type Refresh struct {
	Token     string
	JTI       string
	ClientID  string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TokenStore is the consumer-side state interface for the /token handler (see
// state/doc.go). It is distinct from CallbackStore — the callback side mints
// the auth code; the token side redeems it (single-use) and manages the
// refresh-token lifecycle. The concrete sqlite.Store satisfies it
// structurally; the type is exported only so the composition root can inject
// it via fx.As.
type TokenStore interface {
	// ConsumeAuthCode atomically loads and deletes the authorization code,
	// enforcing single use. It returns ErrAuthCodeNotFound when no row
	// matches. Expiry is the caller's concern (it owns the clock); a
	// consumed-but-expired code is still returned and then rejected.
	ConsumeAuthCode(ctx context.Context, code string) (AuthCode, error)

	// SaveRefresh persists a freshly minted refresh token.
	SaveRefresh(ctx context.Context, r Refresh) error

	// ConsumeRefresh atomically loads and deletes the refresh token,
	// enforcing single use so every exchange rotates the token. It returns
	// ErrRefreshNotFound when no row matches.
	ConsumeRefresh(ctx context.Context, token string) (Refresh, error)
}

// Token serves POST /token: it completes the authorization-code flow by
// exchanging a redeemed code (PKCE-verified) for a signed JWT, and renews
// sessions via the refresh-token grant.
type Token struct {
	store      TokenStore
	signer     *keys.Signer
	now        func() time.Time
	newRefresh func() (string, error)
}

type TokenOption func(*Token)

// WithTokenClock swaps the clock used for expiry checks and refresh-token
// timestamps. For tests.
func WithTokenClock(now func() time.Time) TokenOption {
	return func(t *Token) { t.now = now }
}

// WithRefreshGenerator swaps the opaque refresh-token generator. For tests.
func WithRefreshGenerator(fn func() (string, error)) TokenOption {
	return func(t *Token) { t.newRefresh = fn }
}

func NewToken(store TokenStore, signer *keys.Signer, opts ...TokenOption) *Token {
	t := &Token{
		store:      store,
		signer:     signer,
		now:        func() time.Time { return time.Now().UTC() },
		newRefresh: randomRefresh,
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// tokenInput takes the raw form body verbatim: OAuth2 §4.1.3 mandates
// application/x-www-form-urlencoded, and parsing it by hand keeps the
// grant-type dispatch explicit rather than bending huma's JSON schema around
// two mutually exclusive parameter sets.
type tokenInput struct {
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// tokenOutput is the RFC 6749 §5.1 token response. The no-store/no-cache
// headers are mandated by §5.1 so intermediaries never retain a bearer token.
type tokenOutput struct {
	CacheControl string `header:"Cache-Control"`
	Pragma       string `header:"Pragma"`
	Body         tokenResponse
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	// IDToken is the same signed JWT as AccessToken. tempogate issues one
	// token that is simultaneously the OAuth2 access token and the OIDC
	// id_token; relying parties (Temporal) verify it the same way either
	// way, so minting a second token would only add surface area.
	IDToken string `json:"id_token"`
}

func (t *Token) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "token",
		Method:      http.MethodPost,
		Path:        tokenPath,
		Summary:     "OAuth2 token endpoint (authorization_code + refresh_token grants)",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *tokenInput) (*tokenOutput, error) {
		return t.handle(ctx, in)
	})
}

func (t *Token) handle(ctx context.Context, in *tokenInput) (*tokenOutput, error) {
	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "malformed form body")
	}

	switch form.Get("grant_type") {
	case grantAuthorizationCode:
		return t.authorizationCodeGrant(ctx, form)
	case grantRefreshToken:
		return t.refreshTokenGrant(ctx, form)
	case "":
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		return nil, oauthErr(http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported")
	}
}

func (t *Token) authorizationCodeGrant(ctx context.Context, form url.Values) (*tokenOutput, error) {
	code := form.Get("code")
	if code == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code is required")
	}
	verifier := form.Get("code_verifier")
	if verifier == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code_verifier is required (PKCE)")
	}

	ac, err := t.store.ConsumeAuthCode(ctx, code)
	if errors.Is(err, ErrAuthCodeNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-redeemed authorization code")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume auth code: %w", err)
	}

	if t.now().After(ac.ExpiresAt) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "authorization code expired")
	}
	if form.Get("client_id") != ac.ClientID {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "client_id does not match the authorization request")
	}
	if form.Get("redirect_uri") != ac.RedirectURI {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
	}
	if !verifyPKCE(verifier, ac.CodeChallenge) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
	}

	return t.issue(ctx, ac.Email, ac.ClientID)
}

func (t *Token) refreshTokenGrant(ctx context.Context, form url.Values) (*tokenOutput, error) {
	token := form.Get("refresh_token")
	if token == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "refresh_token is required")
	}

	rt, err := t.store.ConsumeRefresh(ctx, token)
	if errors.Is(err, ErrRefreshNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-used refresh token")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume refresh token: %w", err)
	}

	if t.now().After(rt.ExpiresAt) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "refresh token expired")
	}

	return t.issue(ctx, rt.Email, rt.ClientID)
}

// issue mints the access/id token and a rotated refresh token, persisting the
// latter before responding. It is the single place token shape and lifetimes
// are decided, so the two grants cannot drift apart.
func (t *Token) issue(ctx context.Context, email, clientID string) (*tokenOutput, error) {
	signed, jti, err := t.signer.Mint(ctx, keys.MintRequest{
		Subject:     email,
		Email:       email,
		TTL:         accessTokenTTL,
		Permissions: flatAdminPermissions(),
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: mint access token: %w", err)
	}

	refreshTok, err := t.newRefresh()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate refresh token: %w", err)
	}

	now := t.now()
	if err := t.store.SaveRefresh(ctx, Refresh{
		Token:     refreshTok,
		JTI:       jti,
		ClientID:  clientID,
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}); err != nil {
		return nil, fmt.Errorf("oidc: persist refresh token: %w", err)
	}

	return &tokenOutput{
		CacheControl: "no-store",
		Pragma:       "no-cache",
		Body: tokenResponse{
			AccessToken:  signed,
			TokenType:    "Bearer",
			ExpiresIn:    int(accessTokenTTL.Seconds()),
			RefreshToken: refreshTok,
			IDToken:      signed,
		},
	}, nil
}

// flatAdminPermissions is the Hour-0 authorization model: every admitted
// identity gets unconditional access across all namespaces. Group- or
// role-derived grants will replace this once the shared permissions model
// lands; until then the Temporal-formatted claim is constructed inline rather
// than through that (not-yet-existing) package.
func flatAdminPermissions() []string {
	return []string{"*:admin"}
}

// verifyPKCE checks the RFC 7636 S256 binding: BASE64URL(SHA256(verifier))
// must equal the challenge stored at /authorize. /authorize rejects any
// method other than S256, so plain is unreachable here. The compare is
// constant-time so a mismatch leaks no timing signal about the challenge.
func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func randomRefresh() (string, error) {
	b := make([]byte, refreshEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
