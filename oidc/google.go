package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Upstream is the Google leg of the flow, behind an interface so the callback
// handler can be unit-tested without a real Google and the integration test
// can point the real implementation at a mock IdP.
type Upstream interface {
	// ExchangeAndVerify swaps a Google authorization code for an id_token,
	// verifies its signature and claims against Google's JWKS, and returns
	// the email it asserts. emailVerified reflects the token's
	// `email_verified` claim — an unverified email must not be trusted by
	// the domain gate even if the domain matches.
	ExchangeAndVerify(ctx context.Context, code string) (email string, emailVerified bool, err error)
}

// googleUpstream wraps golang.org/x/oauth2 (code → id_token) and
// coreos/go-oidc (id_token signature + claims verification). The OIDC
// provider is resolved lazily on first use: discovery is a network call we
// must not make at fx graph-construction time.
type googleUpstream struct {
	oauth       *oauth2.Config
	issuerURL   string
	clientID    string
	once        sync.Once
	verifier    *coreosoidc.IDTokenVerifier
	verifierErr error
}

// NewGoogleUpstream builds the production Upstream. tokenEndpoint and
// issuerURL are injected (not hardcoded to Google) so the end-to-end test can
// substitute a mock; in production they default to Google's real endpoints
// via config defaults. redirectURL must equal the redirect_uri sent at
// /authorize, or Google rejects the exchange.
func NewGoogleUpstream(clientID, clientSecret, tokenEndpoint, redirectURL, issuerURL string) Upstream {
	return &googleUpstream{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   google.Endpoint.AuthURL,
				TokenURL:  tokenEndpoint,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: redirectURL,
			Scopes:      strings.Fields(googleScope),
		},
		issuerURL: strings.TrimRight(issuerURL, "/"),
		clientID:  clientID,
	}
}

func (g *googleUpstream) ExchangeAndVerify(ctx context.Context, code string) (string, bool, error) {
	tok, err := g.oauth.Exchange(ctx, code)
	if err != nil {
		return "", false, fmt.Errorf("oidc: google code exchange: %w", err)
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return "", false, errors.New("oidc: google token response missing id_token")
	}

	verifier, err := g.idVerifier(ctx)
	if err != nil {
		return "", false, err
	}

	idToken, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return "", false, fmt.Errorf("oidc: verify google id_token: %w", err)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", false, fmt.Errorf("oidc: decode google id_token claims: %w", err)
	}
	if claims.Email == "" {
		return "", false, errors.New("oidc: google id_token has no email claim")
	}
	return claims.Email, claims.EmailVerified, nil
}

// idVerifier lazily performs OIDC discovery against issuerURL and caches the
// resulting verifier. A discovery failure is cached too: a misconfigured or
// unreachable issuer should fail every callback the same way, not retry-storm.
func (g *googleUpstream) idVerifier(ctx context.Context) (*coreosoidc.IDTokenVerifier, error) {
	g.once.Do(func() {
		provider, err := coreosoidc.NewProvider(ctx, g.issuerURL)
		if err != nil {
			g.verifierErr = fmt.Errorf("oidc: google discovery (%s): %w", g.issuerURL, err)
			return
		}
		g.verifier = provider.Verifier(&coreosoidc.Config{ClientID: g.clientID})
	})
	return g.verifier, g.verifierErr
}
