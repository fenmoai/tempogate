package oidc

import (
	"context"
	"errors"
	"time"
)

// ErrAuthRequestNotFound is returned by ConsumeAuthRequest when no pending
// request matches the given internal state — because the state was never
// issued, has already been consumed (single-use), or its row was reaped.
// The callback maps this to a 400 without distinguishing the cases, so a
// replayed state is indistinguishable from a forged one to the caller.
var ErrAuthRequestNotFound = errors.New("oidc: auth request not found")

// AuthCode is the authorization code tempogate mints after Google has
// authenticated the user and the email passed the domain allowlist. It is
// single-use and short-lived: the downstream /token call (a later epic)
// exchanges it — together with the PKCE verifier matching CodeChallenge —
// for a signed JWT. Email is the verified upstream identity flat authz keys
// off in v1.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Email               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// CallbackStore is the consumer-side state interface for the /callback/google
// handler (see state/doc.go). It is distinct from AuthRequestStore — the
// authorize side only writes pending requests; the callback side consumes one
// (single-use) and persists the minted code. The concrete sqlite.Store
// satisfies it structurally; the type is exported only so the composition
// root can inject it via fx.As.
type CallbackStore interface {
	// ConsumeAuthRequest atomically loads and deletes the pending request
	// keyed by internalState, enforcing single use. It returns
	// ErrAuthRequestNotFound when no row matches. Expiry is the caller's
	// concern (it owns the clock); a consumed-but-expired request is still
	// returned and then rejected by the handler.
	ConsumeAuthRequest(ctx context.Context, internalState string) (AuthRequest, error)

	// SaveAuthCode persists a freshly minted authorization code.
	SaveAuthCode(ctx context.Context, ac AuthCode) error
}
