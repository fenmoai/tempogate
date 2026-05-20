package keys

import "context"

// DenylistChecker is the consumer-side state interface the Verifier and the
// DenylistCache consult to decide whether a JWT's jti has been revoked.
//
// Per the project's consumer-defined-interface convention (see state/doc.go),
// the interface lives next to the package that uses it. The concrete sqlite
// store satisfies it structurally via its own IsRevoked method; the type is
// exported so the composition root can wire it via fx.As.
type DenylistChecker interface {
	// IsRevoked returns true when jti has been recorded in the persistent
	// denylist. A nil error with a false return means "not revoked": the
	// caller does not need to inspect the error to branch on the answer.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
