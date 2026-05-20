package admin

import (
	"context"
	"errors"
)

// ErrIntegrationKeyNotFound is the consumer sentinel the sqlite layer wraps
// (via fmt.Errorf("%w: ...", admin.ErrIntegrationKeyNotFound, id)) when ByID
// or MarkRevoked is given an unknown id. Handlers errors.Is against it to
// emit 404 without coupling to the storage layer's wording.
var ErrIntegrationKeyNotFound = errors.New("admin: integration key not found")

// ListFilter narrows the set returned by KeyRegistry.List. Empty Owner /
// Namespace mean "do not filter on that axis". Limit is the page size; the
// store binds limit+1 at the SQL layer so the handler can detect "has more"
// without a second COUNT round trip. Cursor is the opaque last-seen id from
// the previous page (the bare UUIDv7); empty means first page. See keys.go
// for the handler-side defaults (limit cap, cursor validation).
type ListFilter struct {
	Owner     string
	Namespace string
	Limit     int
	Cursor    string
}

// KeyRegistry is the narrow store contract admin/ depends on, per
// state/doc.go's consumer-defined-interface convention. The method names are
// deliberately short and domain-local — the consumer (admin) names them for
// what they mean in its own world (Save, ByID, List, MarkRevoked), and a
// thin adapter in state/sqlite translates each call to the prefixed methods
// on sqlite.Store (SaveIntegrationKey, …) so multiple consumers can reuse
// short names without colliding on the multi-purpose Store. No package
// imports state/.
//
// Save persists a fully-stamped IntegrationKey (ID, JTI, CreatedAt set by
// the POST handler). ByID returns ErrIntegrationKeyNotFound for unknown ids.
// List honours every set field on ListFilter and returns rows in id-DESC
// order, fetching limit+1 rows so the handler can detect "has more" without
// a second COUNT round trip. MarkRevoked is idempotent: a second call
// against an already-revoked id returns the original jti without re-stamping
// revoked_at, so any downstream denylist enqueue keyed on jti can call it
// safely on every revoke request.
type KeyRegistry interface {
	Save(ctx context.Context, k IntegrationKey) error
	ByID(ctx context.Context, id string) (IntegrationKey, error)
	List(ctx context.Context, f ListFilter) ([]IntegrationKey, error)
	MarkRevoked(ctx context.Context, id string) (jti string, err error)
}

// DenylistHydrator pushes a freshly-revoked jti into any in-process verifier
// cache so the next /userinfo or refresh-token call rejects the revoked
// token immediately rather than waiting for the cache TTL to expire. The
// production wiring satisfies this with *keys.DenylistCache.Hydrate; tests
// can pass nil to skip cache hydration (storage alone is sufficient for the
// revoke-takes-effect-eventually contract).
type DenylistHydrator interface {
	Hydrate(jti string)
}
