package keys

import "context"

// keyStore is the consumer-side state interface for this package.
//
// Per the convention documented in package state, interfaces live with the
// package that uses them; the concrete store will satisfy this structurally
// without importing keys/.
type keyStore interface {
	SaveKeypair(ctx context.Context, kp Keypair) error
	LoadKeypairs(ctx context.Context) ([]Keypair, error)
}
