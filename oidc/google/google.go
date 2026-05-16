// Package google is the concrete Google leg of the OIDC flow. It wraps
// golang.org/x/oauth2 (code → id_token) and coreos/go-oidc (id_token
// signature + claims verification) and structurally satisfies
// oidc.Upstream, the consumer-side interface defined in package oidc — the
// same provider/consumer split state/sqlite uses, so package oidc never has
// to import oauth2 or go-oidc.
package google

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	xgoogle "golang.org/x/oauth2/google"
)

const scopes = "openid email"

// Client exchanges a Google authorization code for a verified email. The
// OIDC provider is resolved lazily on first use: discovery is a network call
// we must not make at fx graph-construction time.
type Client struct {
	oauth       *oauth2.Config
	issuerURL   string
	clientID    string
	once        sync.Once
	verifier    *coreosoidc.IDTokenVerifier
	verifierErr error
}

// New builds the production client. tokenEndpoint and issuerURL are injected
// (not hardcoded to Google) so the end-to-end test can substitute a mock; in
// production they default to Google's real endpoints via config defaults.
// redirectURL must equal the redirect_uri sent at /authorize, or Google
// rejects the exchange.
func New(clientID, clientSecret, tokenEndpoint, redirectURL, issuerURL string) *Client {
	return &Client{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   xgoogle.Endpoint.AuthURL,
				TokenURL:  tokenEndpoint,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: redirectURL,
			Scopes:      strings.Fields(scopes),
		},
		issuerURL: strings.TrimRight(issuerURL, "/"),
		clientID:  clientID,
	}
}

// ExchangeAndVerify swaps a Google authorization code for an id_token,
// verifies its signature and claims against Google's JWKS, and returns the
// email it asserts. emailVerified reflects the token's `email_verified`
// claim — an unverified email must not be trusted by the domain gate even if
// the domain matches.
func (c *Client) ExchangeAndVerify(ctx context.Context, code string) (string, bool, error) {
	tok, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return "", false, fmt.Errorf("google: code exchange: %w", err)
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return "", false, errors.New("google: token response missing id_token")
	}

	verifier, err := c.idVerifier(ctx)
	if err != nil {
		return "", false, err
	}

	idToken, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return "", false, fmt.Errorf("google: verify id_token: %w", err)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", false, fmt.Errorf("google: decode id_token claims: %w", err)
	}
	if claims.Email == "" {
		return "", false, errors.New("google: id_token has no email claim")
	}
	return claims.Email, claims.EmailVerified, nil
}

// idVerifier lazily performs OIDC discovery against issuerURL and caches the
// resulting verifier. A discovery failure is cached too: a misconfigured or
// unreachable issuer should fail every callback the same way, not retry-storm.
func (c *Client) idVerifier(ctx context.Context) (*coreosoidc.IDTokenVerifier, error) {
	c.once.Do(func() {
		provider, err := coreosoidc.NewProvider(ctx, c.issuerURL)
		if err != nil {
			c.verifierErr = fmt.Errorf("google: discovery (%s): %w", c.issuerURL, err)
			return
		}
		c.verifier = provider.Verifier(&coreosoidc.Config{ClientID: c.clientID})
	})
	return c.verifier, c.verifierErr
}
